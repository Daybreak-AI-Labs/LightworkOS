"""Owner-scoped finite decision reviews, shared budgets and original receipts."""
from __future__ import annotations

import copy
import hmac
import json
import re
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from maverick import config, crypto_at_rest, killswitch
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.governed_records import (
    GovernedRecordStore,
    LocalGovernedRecordBackend,
    PostgresGovernedRecordBackend,
)
from maverick.robust_decisions import amount, binding, decimal, evaluate
from maverick.shared_decision_evidence import Solver, check_certificate, validate

from . import auth
from .draft_api import context_for

STORE = GovernedRecordStore("shared-decision-evidence", "SDE", "shared_decision_evidence")
TTL = 600
NOTICE = "This checks the choices and possible situations you entered, using your attributed reports. It does not independently verify business facts, reserve resources, send questions, or carry out a choice. Checking each case separately does not show that shared resources can fulfil all cases; enter combined requirements or use Promise reviews."
CHECK_LIMIT = 100
ACTION_LABELS = {"create": "New decision review", "edit": "Changed entered choices", "consent": "Source use allowed", "withdraw": "Source use withdrawn", "refresh": "Source reviewed again", "acquire": "Single observation reserved", "answer": "Operator observation recorded", "remove": "Decision review removed", "qualify": "Complete loss check", "acquire_batch": "Complete observation batch", "acknowledge": "Unconfirmed check acknowledged", "unconfirmed create": "New review admission unconfirmed"}


def _robust_binding(payload):
    return binding(payload["model"], payload["sources"], payload["pending"], payload["questions_used"],
                   payload["effort_used"], payload.get("cost_used", "0.00"))


def _robust_current(payload, now):
    value = payload.get("robust_result")
    if (value and not payload.get("robust_hold") and value["binding"] == _robust_binding(payload)
            and value["result"].get("checked_before", 0) > now):
        return value["result"]
    return {"status": "unknown", "cases": [], "batch": None,
            "reason": "Read the unconfirmed original before a separately reviewed acknowledgment." if payload.get("robust_hold") else
            "The entered losses have not been checked against these exact current reports, permissions, dates and remaining allowance.",
            "business_verified": False}


def authority(request, context=None, *, historical=False):
    auth.require_permission(request, "operate")
    current = context_for(request)
    if context is not None and not hmac.compare_digest(context, current):
        raise HTTPException(409, "Your account or workspace changed. Reload this review.")
    if not historical and (config.config_source_errors(include_tenant=True) or config.get_features().get("shared_decision_evidence") is not True):
        raise HTTPException(403, "Shared decision reviews are off. An administrator can enable them in Settings.")
    return auth.caller_principal(request) or "local:dashboard", current


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    if not isinstance(identifier, str) or not re.fullmatch(r"SDE-[a-f0-9]{32}", identifier):
        raise HTTPException(404, "This decision review is unavailable.")
    row = STORE.get(identifier)
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This decision review is unavailable to your account and workspace.")
    if row.get("_audit_pending"):
        row = STORE._flush(row)
    return row


def _open(row):
    material = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if material["identity"] != [row["id"], row["actor"], row["context"]]:
        raise HTTPException(409, "The saved review's source binding could not be verified.")
    return material["payload"]


def _seal(row, payload):
    raw = json.dumps({"identity": [row["id"], row["actor"], row["context"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(raw.encode("utf-8")) > 400000:
        raise HTTPException(413, "This complete review is too large. Nothing was changed; no details were dropped.")
    row["envelope"] = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Turn on encryption for stored data before retaining a decision review.")


def _source(fact, now):
    return {"definition": digest(fact), "revision": digest([fact, now]), "observed_at": now,
            "expires_at": now + fact["fresh_hours"] * 3600, "available": True, "consent_cases": [],
            "value": None, "quality": "operator_supplied"}


def _solver(payload, now=None):
    return Solver(payload["model"], payload["sources"], time.time() if now is None else now,
                  questions_used=payload["questions_used"], effort_used=payload["effort_used"],
                  pending_facts=(row["fact"] for row in payload["pending"].values() if row["state"] == "awaiting_observation"))


def _evaluation(payload):
    solver = _solver(payload)
    assessment = solver.assessment()
    certificates = assessment["certificates"]
    current_ids = {row.get("id") for row in certificates}
    retained = []
    for old in payload.get("certificate_history", {}).values():
        if old["id"] not in current_ids:
            retained.append({"case": old["case"], "id": old["id"], "still_valid": check_certificate(old, payload["model"], payload["sources"], solver.now),
                             "meaning": "Retained model certificate, not an independent business attestation."})
    return {**assessment, "prior_certificates": retained, "acquisition": solver.acquisition(),
            "robust": _robust_current(payload, solver.now) if "robust" in payload["model"] else None,
            "checks_used": payload.get("checks_used", 0), "check_limit": CHECK_LIMIT,
            "cost_used": payload.get("cost_used", "0.00"), "check_hold": payload.get("robust_hold")}


def view(request, identifier):
    row = _owned(request, identifier)
    payload = _open(row)
    references = [{"operation": key, "action": receipt["action"], "recorded_at": receipt["recorded_at"]}
                  for key, receipt in payload["operations"].items()]
    if payload.get("reservation"):
        references.append({"operation": payload["reservation"]["operation"], "action": "unconfirmed create", "recorded_at": row["created_at"]})
    value = {"id": row["id"], "revision": row["revision"], "context": row["context"], "removed": payload["removed"],
        "model": payload["model"], "sources": payload["sources"], "pending": payload["pending"],
        "evaluation": _evaluation(payload) if not payload["removed"] and not payload.get("reservation") else None, "notice": NOTICE,
        "unconfirmed_admission": bool(payload.get("reservation")),
        "audit_pending": bool(row.get("_audit_pending")), "original_requests": references}
    authority(request, row["context"])
    return value


def listing(request):
    actor, context = authority(request)
    values = STORE.list(limit=101)
    if len(values) > 100:
        raise HTTPException(409, "This workspace reached the 100-review finite pilot limit. No saved reviews were silently dropped.")
    return {"context": context, "reviews": [{"id": row["id"], "title": _open(row)["model"]["title"],
        "removed": _open(row)["removed"], "unconfirmed_admission": bool(_open(row).get("reservation"))}
        for row in values if (row.get("actor"), row.get("context")) == (actor, context)]}


def historical_requests(request):
    """Own original references only; current model consent/freshness is not replay authority."""
    actor, context = authority(request, historical=True)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "This workspace exceeds the finite history bound. No requests were silently dropped.")
    choices = []
    for row in rows:
        if (row.get("actor"), row.get("context")) != (actor, context):
            continue
        payload = _open(row)
        references = dict(payload["operations"])
        if payload.get("reservation"):
            references[payload["reservation"]["operation"]] = {"action": "unconfirmed create", "recorded_at": row["created_at"]}
        for operation, receipt in references.items():
            choices.append({"value": row["id"] + "|" + operation,
                "label": payload["model"]["title"] + " · " + ACTION_LABELS[receipt["action"]] + " · " +
                    datetime.fromtimestamp(receipt["recorded_at"], timezone.utc).isoformat()})
    authority(request, context, historical=True)
    return {"context": context, "choices": choices}


def author_handoff(request, identifier=""):
    actor, context = authority(request)
    row = _owned(request, identifier) if identifier else None
    source = [row["revision"], digest(_open(row))] if row else None
    authority(request, context)
    return {"context": context, "binding": digest([actor, context, identifier, source]), "review": identifier}


def _check_arguments(action, arguments, payload=None):
    if action in {"create", "edit"}:
        validate(arguments)
        if any(case["due_at"] <= time.time() for case in arguments["cases"]):
            raise HTTPException(422, "Choose future decision deadlines.")
        if payload and payload.get("cost_unit") and ("robust" not in arguments or arguments["robust"]["unit"] != payload["cost_unit"]):
            raise HTTPException(409, "Earlier observation costs remain spent in their original unit. Keep that same unit; editing or removing cannot reset the allowance.")
        return
    allowed = {"consent": {"fact", "cases"}, "withdraw": {"fact", "cases"}, "refresh": {"fact"}, "acquire": set(),
               "answer": {"request", "value", "basis"}, "remove": set(),
               "qualify": set(), "acquire_batch": set(), "acknowledge": set()}
    if action not in allowed or set(arguments) != allowed[action]:
        raise HTTPException(422, "Choose one complete decision-review operation.")
    if action in {"consent", "withdraw"}:
        if (arguments["fact"] not in payload["sources"] or not isinstance(arguments["cases"], list)
                or not arguments["cases"] or len(set(arguments["cases"])) != len(arguments["cases"])
                or set(arguments["cases"]) - {case["id"] for case in payload["model"]["cases"]}):
            raise HTTPException(422, "Choose this fact and its exact permitted cases.")
    if action == "refresh" and arguments["fact"] not in payload["sources"]:
        raise HTTPException(422, "Choose an exact current source fact.")
    if action == "answer":
        pending = payload["pending"].get(arguments["request"])
        if (not pending or pending["state"] != "awaiting_observation" or type(arguments["value"]) is not int
                or not isinstance(arguments["basis"], str) or not 10 <= len(arguments["basis"].strip()) <= 2000):
            raise HTTPException(422, "Choose an open observation, a possible quantity and the basis for your report.")
        fact = next(item for item in payload["model"]["facts"] if item["id"] == pending["fact"])
        if arguments["value"] not in fact["values"]:
            raise HTTPException(422, "The reported value is outside this model. Edit the complete model instead.")
    if action == "acquire" and "robust" in payload["model"]:
        raise HTTPException(409, "This review includes loss and observation costs. Use its checked complete observation batch so every declared allowance is counted.")
    if action in {"qualify", "acquire_batch"} and "robust" not in payload["model"]:
        raise HTTPException(409, "Enter the complete loss and observation-cost table first.")
    if action == "qualify" and payload.get("checks_used", 0) >= CHECK_LIMIT:
        raise HTTPException(409, "The shared lifetime allowance of 100 complete loss checks is exhausted. Editing and removal do not refund earlier checks.")
    if action == "acquire_batch":
        selected = _robust_current(payload, time.time()).get("batch")
        if not selected or not selected["facts"]:
            raise HTTPException(409, "No current checked, affordable observation batch is available. Check the complete current loss table first.")
    if action == "acknowledge" and not payload.get("robust_hold"):
        raise HTTPException(409, "There is no unconfirmed loss check to acknowledge.")


def prepare(request, action, arguments, identifier=None):
    with authority_effect_fence():
        actor, context = authority(request)
        row = _owned(request, identifier) if identifier else None
        payload = _open(row) if row else None
        if action != "create" and row is None or action == "create" and row is not None:
            raise HTTPException(422, "Choose a saved review or create a new one.")
        if row and (row.get("_audit_pending") or payload["removed"] or payload.get("reservation")):
            raise HTTPException(409, "This review is removed or its original activity receipt is pending. Read its original result.")
        if payload and payload.get("robust_hold") and action not in {"acknowledge", "withdraw", "remove"}:
            raise HTTPException(409, "The earlier loss check is unconfirmed. Read that exact original, then separately review an acknowledgment; its earlier allowance stays spent.")
        _check_arguments(action, arguments, payload)
        if action == "acquire" and not _solver(payload).acquisition()["selected"]:
            raise HTTPException(409, "No affordable observation can currently resolve a modeled case. The result stays unknown.")
        return {"action": action, "arguments": copy.deepcopy(arguments), "id": identifier, "revision": row["revision"] if row else None,
                "actor": actor, "context": context, "expires": time.time() + TTL,
                "source_digest": digest(payload) if payload else None,
                "source_review": {"model": payload["model"], "sources": payload["sources"],
                    "budget": _solver(payload).assessment()["budget"], "cost_used": payload.get("cost_used", "0.00"),
                    "checks_used": payload.get("checks_used", 0), "check_limit": CHECK_LIMIT,
                    "unconfirmed_check": payload.get("robust_hold")} if payload else None,
                "selection": _solver(payload).acquisition()["selected"] if action == "acquire" else
                    _robust_current(payload, time.time()).get("batch") if action == "acquire_batch" else None}


def review_changes(prepared):
    labels = {"create": "Save all entered choices", "edit": "Replace the complete entered choices", "consent": "Allow source use",
        "withdraw": "Withdraw source use", "refresh": "Review a source again", "acquire": "Reserve one observation", "answer": "Record a reported observation",
        "remove": "Remove this review", "qualify": "Check all entered losses and observation batches", "acquire_batch": "Reserve the complete selected observation batch",
        "acknowledge": "Acknowledge an unconfirmed loss check without refunding its allowance"}
    rows = [{"label": "Reviewed change", "after": labels[prepared["action"]]}, {"label": "Meaning", "after": NOTICE}]
    source = prepared.get("source_review")
    model = prepared["arguments"] if prepared["action"] in {"create", "edit"} else source["model"]
    _model_rows(rows, model, "Proposed" if prepared["action"] in {"create", "edit"} else "Current")
    if source and prepared["action"] == "edit":
        _model_rows(rows, source["model"], "Current")
    if source:
        _source_rows(rows, source)
    _operation_rows(rows, prepared, model)
    for key, label in (("id", "Saved review reference"), ("revision", "Saved review version"), ("actor", "Person confirming"),
                       ("context", "Account and workspace binding"), ("source_digest", "Current evidence fingerprint")):
        rows.append({"label": label, "after": str(prepared[key]), "section": "recorded"})
    rows.append({"label": "Confirm this review before", "after": _date(prepared["expires"])})
    return rows


def _date(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _situation(model, index):
    state = model["states"][index]
    return "; ".join(fact["name"] + ": " + str(state[fact["id"]]) for fact in model["facts"])


def _model_rows(rows, model, heading):
    rows.extend({"label": heading + " · " + label, "after": str(model[key])} for key, label in (
        ("title", "Review name"), ("question_budget", "Shared question allowance"), ("effort_budget", "Shared effort allowance")))
    facts = {fact["id"]: fact for fact in model["facts"]}
    words = {"at_least": "at least", "at_most": "at most", "equals": "exactly"}
    for fact in facts.values():
        rows.append({"label": heading + " · Fact · " + fact["name"], "after": fact["meaning"] + "\nReported by: " + fact["source"] +
            "\nPossible quantities: " + ", ".join(map(str, fact["values"])) + "\nEffort per observation: " + str(fact["cost"]) +
            "\nReview permission again after: " + str(fact["fresh_hours"]) + " hours. Operator supplied; not independently verified."})
    for case in model["cases"]:
        rows.append({"label": heading + " · Case · " + case["name"], "after": "Decide before " + _date(case["due_at"])})
        for action in case["actions"]:
            rows.append({"label": case["name"] + " · " + action["name"], "after": "Required: " + "; ".join(
                facts[item["fact"]]["name"] + " " + words[item["operator"]] + " " + str(item["value"]) for item in action["conditions"])})
    for index in range(len(model["states"])):
        rows.append({"label": heading + " · Possible situation " + str(index + 1), "after": _situation(model, index)})
    if "robust" in model:
        _loss_rows(rows, model, heading)


def _loss_rows(rows, model, heading):
    value = model["robust"]
    rows.append({"label": heading + " · Entered losses and cost allowance", "after": "One consistent unit: " + value["unit"] +
        "\nMaximum extra loss versus the best feasible entered choice: " + value["epsilon"] +
        "\nLifetime observation-cost allowance: " + value["cost_budget"] +
        "\nAll possibilities and losses are entered assumptions. Separate cases do not prove joint resource availability."})
    for fact in model["facts"]:
        rows.append({"label": heading + " · Cost to observe " + fact["name"], "after": value["observation_costs"][fact["id"]] + " " + value["unit"]})
    for case in model["cases"]:
        for index, losses in enumerate(value["losses"][case["id"]]):
            rows.append({"label": heading + " · " + case["name"] + " · Situation " + str(index + 1),
                "after": _situation(model, index) + "\nEntered losses: " + "; ".join(
                    action["name"] + ": " + losses[action["id"]] + " " + value["unit"] for action in case["actions"])})


def _source_rows(rows, source):
    cases = {case["id"]: case["name"] for case in source["model"]["cases"]}
    for fact in source["model"]["facts"]:
        value = source["sources"][fact["id"]]
        rows.append({"label": "Current permission and report · " + fact["name"], "after":
            "Allowed cases: " + (", ".join(cases[key] for key in value["consent_cases"]) or "None") +
            "\nReported quantity: " + (str(value["value"]) if value["value"] is not None else "Unknown") +
            "\nAvailable for use: " + ("Yes" if value["available"] else "No") +
            "\nReviewed: " + _date(value["observed_at"]) + "\nExpires: " + _date(value["expires_at"]) +
            "\nReport basis: " + value.get("basis", "No observation reported") + "\nIndependent business verification: No"})
        rows.append({"label": "Recorded evidence for " + fact["name"], "after": "Version: " + value["revision"] +
            "\nMeaning fingerprint: " + value["definition"], "section": "recorded"})
    rows.append({"label": "Current remaining question and effort allowance", "after": str(source["budget"]["questions_left"]) +
        " questions; " + str(source["budget"]["effort_points_left"]) + " effort points"})
    rows.append({"label": "Earlier costs and complete loss checks remain spent", "after": source["cost_used"] + " in the entered cost unit; " +
        str(source["checks_used"]) + " of " + str(source["check_limit"]) + " lifetime checks"})
    if source["unconfirmed_check"]:
        rows.append({"label": "Earlier check is unconfirmed", "after": "Acknowledgment will release its hold only. The original stays unknown and its allowance is not refunded."})


def _operation_rows(rows, prepared, model):
    action, arguments = prepared["action"], prepared["arguments"]
    facts = {fact["id"]: fact["name"] for fact in model["facts"]}
    cases = {case["id"]: case for case in model["cases"]}
    if action in {"consent", "withdraw", "refresh"}:
        rows.append({"label": "Selected fact", "after": facts[arguments["fact"]]})
        if "cases" in arguments:
            rows.append({"label": "Exact selected cases", "after": "; ".join(cases[key]["name"] for key in arguments["cases"])})
    if action == "answer":
        rows.extend([{"label": "Reported possible quantity", "after": str(arguments["value"])},
                     {"label": "Basis for this operator report", "after": arguments["basis"]},
                     {"label": "Original observation reference", "after": arguments["request"], "section": "recorded"}])
    selected = prepared["selection"]
    if action == "acquire" and selected:
        rows.append({"label": "Selected observation", "after": facts[selected["fact"]] + "; effort: " + str(selected["cost"]) +
            "; cases supported in the least helpful entered outcome: " + str(selected["worst_case_new_cases"])})
        for row in selected["branches"]:
            rows.append({"label": "Possible reported quantity " + str(row["value"]), "after": "; ".join(cases[key]["name"] for key in row["new_cases"]) or "No newly supported case"})
    if action == "acquire_batch" and selected:
        rows.append({"label": "Complete observation batch to reserve", "after": "; ".join(facts[key] for key in selected["facts"]) +
            "\nCost: " + selected["cost"] + " " + model["robust"]["unit"] + "; effort: " + str(selected["effort_points"]) +
            "; questions: " + str(selected["questions"]) + ". These allowances are spent once; answers are still unknown."})
        for index, cell in enumerate(selected["cells"]):
            rows.append({"label": "Possible joint answer " + str(index + 1), "after": "; ".join(facts[key] + ": " + str(value) for key, value in cell["answers"].items())})
            for row in cell["cases"]:
                case = cases[row["case"]]
                rows.append({"label": "Joint answer " + str(index + 1) + " · " + case["name"], "after": "Supported entered choices: " +
                    "; ".join(choice["name"] for choice in case["actions"] if choice["id"] in row["choices"]) +
                    "; remaining situations: " + str(row["remaining_states"])})


def _mutate(payload, prepared, operation, now):
    action, values = prepared["action"], prepared["arguments"]
    if action in {"acquire_batch", "acknowledge"}:
        _mutate_robust(payload, prepared, operation, now)
        return
    if action == "edit":
        previous = payload["sources"]
        payload["model"] = copy.deepcopy(values)
        payload["sources"] = {fact["id"]: previous[fact["id"]] if fact["id"] in previous and previous[fact["id"]]["definition"] == digest(fact)
                              else _source(fact, now) for fact in values["facts"]}
        for source in payload["sources"].values():
            source["consent_cases"] = [case for case in source["consent_cases"] if case in {row["id"] for row in values["cases"]}]
        for row in payload["pending"].values():
            if row["state"] == "awaiting_observation":
                row["state"] = "unconfirmed_after_model_change"
    elif action in {"consent", "withdraw"}:
        source = payload["sources"][values["fact"]]
        current = set(source["consent_cases"])
        source["consent_cases"] = sorted(current | set(values["cases"]) if action == "consent" else current - set(values["cases"]))
        if "robust" in payload["model"]:
            source["revision"] = digest([source["revision"], operation, source["consent_cases"]])
    elif action == "refresh":
        fact = next(item for item in payload["model"]["facts"] if item["id"] == values["fact"])
        source = _source(fact, now)
        source["consent_cases"] = list(payload["sources"][fact["id"]]["consent_cases"])
        payload["sources"][fact["id"]] = source
        for row in payload["pending"].values():
            if row["fact"] == fact["id"] and row["state"] == "awaiting_observation":
                row["state"] = "unconfirmed_after_source_change"
    elif action == "acquire":
        selected = _solver(payload, now).acquisition()["selected"]
        if not selected or selected != prepared["selection"]:
            raise HTTPException(409, "The observation's usefulness or budget changed. Review it again.")
        fact = selected["fact"]
        payload["questions_used"] += 1
        payload["effort_used"] += selected["cost"]
        payload["pending"][operation] = {"fact": fact, "source_revision": payload["sources"][fact]["revision"],
            "model": digest(payload["model"]), "state": "awaiting_observation", "cost": selected["cost"],
            "consent_cases": list(payload["sources"][fact]["consent_cases"]), "requested_at": now}
    elif action == "answer":
        pending = payload["pending"][values["request"]]
        source = payload["sources"][pending["fact"]]
        if (pending["model"] != digest(payload["model"]) or pending["source_revision"] != source["revision"]
                or not source["observed_at"] <= now < source["expires_at"]
                or pending["consent_cases"] != source["consent_cases"]):
            raise HTTPException(409, "The reviewed source or permission changed or expired. This observation remains unconfirmed; no repeat or budget refund was inferred.")
        source.update(value=values["value"], basis=values["basis"].strip(), revision=digest([source["definition"], operation, values["value"], now]),
                      observed_at=now)
        pending["state"] = "reported_operator_observation"
    elif action == "remove":
        payload["removed"] = True
        for source in payload["sources"].values():
            source["available"] = False
        for row in payload["pending"].values():
            if row["state"] == "awaiting_observation":
                row["state"] = "unconfirmed_after_removal"


def _mutate_robust(payload, prepared, operation, now):
    if prepared["action"] == "acknowledge":
        payload.pop("robust_hold", None)
        payload["robust_result"] = None
        return
    selected = _robust_current(payload, now).get("batch")
    if not selected or selected != prepared["selection"]:
        raise HTTPException(409, "The complete observation batch or remaining allowance changed. Check current losses and review again.")
    payload["questions_used"] += selected["questions"]
    payload["effort_used"] += selected["effort_points"]
    payload["cost_used"] = decimal(amount(payload.get("cost_used", "0.00")) + amount(selected["cost"]))
    payload["cost_unit"] = payload["model"]["robust"]["unit"]
    for fact in selected["facts"]:
        observation = digest([operation, fact])[:32]
        source = payload["sources"][fact]
        payload["pending"][observation] = {"fact": fact, "source_revision": source["revision"], "model": digest(payload["model"]),
            "state": "awaiting_observation", "cost": next(row["cost"] for row in payload["model"]["facts"] if row["id"] == fact),
            "declared_cost": payload["model"]["robust"]["observation_costs"][fact],
            "consent_cases": list(source["consent_cases"]), "requested_at": now, "original_batch": operation}


def _identifier(context, actor, operation):
    return "SDE-" + digest([context, actor, operation])[:32]


def original(request, identifier, operation, *, binding=None):
    row = _owned(request, identifier, historical=True)
    payload = _open(row)
    receipt = payload["operations"].get(operation)
    reservation = payload.get("reservation")
    if reservation and (reservation["operation"] != operation or binding is not None and reservation["binding"] != binding):
        raise HTTPException(409, "This admission belongs to another exact original review.")
    if receipt and binding is not None and receipt["binding"] != binding:
        raise HTTPException(409, "This operation belongs to another exact review.")
    authority(request, row["context"], historical=True)
    confirmed = bool(receipt) and receipt.get("state", "confirmed") == "confirmed" and not row.get("_audit_pending")
    return {"id": identifier, "context": row["context"], "operation": operation, "confirmed": confirmed,
        "receipt": receipt, "message": "The original modeled change is recorded. Reading did not request another observation or repeat a business action." if confirmed else
        "The original result is unconfirmed. Reading does not request an observation, spend budget or repeat a change."}


def _check_guard(request, prepared, budget):
    actor, _context = authority(request, prepared["context"])
    if actor != prepared["actor"] or time.time() >= prepared["expires"]:
        raise HTTPException(409, "The person, workspace or complete review changed or expired. The earlier original cannot be repeated.")
    budget.check()
    killswitch.check()


def _qualify(request, prepared, operation):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    def reserve(row):
        _check_guard(request, prepared, budget)
        payload = _open(row)
        if row.get("_audit_pending") or digest(payload) != prepared["source_digest"] or payload.get("robust_hold"):
            raise HTTPException(409, "Current choices, source permission, reports or original custody changed. Read the earlier original.")
        _check_arguments("qualify", {}, payload)
        if len(payload["operations"]) >= 200:
            raise HTTPException(409, "The 200-decision retained history bound is reached; no original was discarded.")
        payload["checks_used"] = payload.get("checks_used", 0) + 1
        payload["robust_hold"], payload["robust_result"] = operation, None
        payload["operations"][operation] = {"action": "qualify", "state": "unconfirmed", "binding": digest(prepared), "actor": prepared["actor"],
            "context": prepared["context"], "recorded_at": time.time(), "checks_used": payload["checks_used"], "business_verified": False}
        _seal(row, payload)
        _check_guard(request, prepared, budget)
    reserved = STORE.update(prepared["id"], reserve, expected_revision=prepared["revision"], action="shared_decision_check_reserved", actor=prepared["actor"],
        **_write_checks(prepared["source_review"]["model"], lambda: _check_guard(request, prepared, budget)))
    if not reserved or reserved.get("_audit_pending"):
        return original(request, prepared["id"], operation, binding=digest(prepared))
    payload = _open(reserved)
    before = digest(payload)
    def compute_guard():
        killswitch.check()
        if time.time() >= prepared["expires"]:
            raise HTTPException(409, "The complete reviewed check expired. Its original remains unconfirmed; no repeat was authorized.")
    result = evaluate(payload["model"], payload["sources"], time.time(), questions_used=payload["questions_used"], effort_used=payload["effort_used"],
        cost_used=payload.get("cost_used", "0.00"), pending_facts=[row["fact"] for row in payload["pending"].values() if row["state"] == "awaiting_observation"],
        budget=budget, guard=compute_guard)
    if result["status"] == "unknown":
        return original(request, prepared["id"], operation, binding=digest(prepared))
    def finish(row):
        _check_guard(request, prepared, budget)
        current = _open(row)
        if row.get("_audit_pending") or digest(current) != before or result["checked_before"] <= time.time():
            raise HTTPException(409, "Source permission, reports, deadline or custody changed before the checked result could be retained. The earlier original stays unconfirmed.")
        current.pop("robust_hold")
        current["robust_result"] = {"binding": _robust_binding(current), "result": result}
        current["operations"][operation].update(state="confirmed", result_fingerprint=digest(result),
            meaning="Complete entered situations and every joint answer were checked; no business facts independently verified.")
        _seal(row, current)
        _check_guard(request, prepared, budget)
        if result["checked_before"] <= time.time():
            raise HTTPException(409, "A source review or decision deadline expired before custody. The earlier original stays unconfirmed.")
    def completion_guard():
        _check_guard(request, prepared, budget)
        if result["checked_before"] <= time.time():
            raise HTTPException(409, "A source review or decision deadline expired before custody. The earlier original stays unconfirmed.")
    STORE.update(prepared["id"], finish, expected_revision=reserved["revision"], action="shared_decision_check_completed", actor=prepared["actor"],
        **_write_checks(payload["model"], completion_guard))
    return original(request, prepared["id"], operation, binding=digest(prepared))


def recover(request, prepared, operation):
    identifier = prepared["id"] or _identifier(prepared["context"], prepared["actor"], operation)
    try:
        return original(request, identifier, operation, binding=digest(prepared))
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise


def apply(request, prepared, operation):
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "The original request reference is missing.")
    with authority_effect_fence():
        actor, context = authority(request, prepared["context"])
        if actor != prepared["actor"]:
            raise HTTPException(403, "Only the exact person who reviewed this model may confirm it.")
        existing = recover(request, prepared, operation)
        if existing and (existing["receipt"] or prepared["action"] == "create"):
            return existing
        if prepared["action"] == "qualify":
            return _qualify(request, prepared, operation)
        def guard():
            authority(request, context)
            if time.time() >= prepared["expires"]:
                raise HTTPException(409, "This exact review expired. Review current sources and budget again.")
        guard()
        identifier = prepared["id"] or _identifier(context, actor, operation)
        checked_effect = {}
        def physical_guard():
            guard()
            if checked_effect:  # Postgres also checks authority before mutation.
                _fresh_effect(prepared, checked_effect["before"], checked_effect["after"])
        def effect(current):
            guard()
            payload = _open(current)
            if current.get("_audit_pending") or digest(payload) != prepared["source_digest"]:
                raise HTTPException(409, "The source model, facts, consent or budget changed. Nothing was repeated.")
            _check_arguments(prepared["action"], prepared["arguments"], payload)
            before = copy.deepcopy(payload)
            _mutate(payload, prepared, operation, time.time())
            _complete(current, payload)
            guard()
            _fresh_effect(prepared, before, payload)
            checked_effect.update(before=before, after=payload)
        def _complete(row, payload):
            if len(payload["operations"]) >= 200:
                raise HTTPException(409, "This review reached its 200-decision custody bound. No history was dropped.")
            assessment = _solver(payload).assessment() if not payload["removed"] else {"certificates": []}
            history = payload.setdefault("certificate_history", {})
            for prior in payload["certificates"]:
                history[prior["case"]] = prior
            payload["certificates"] = [item for item in assessment["certificates"] if item["status"] == "model_sufficient"]
            payload["operations"][operation] = {"action": prepared["action"], "state": "confirmed", "binding": digest(prepared), "actor": actor, "context": context,
                "recorded_at": time.time(), "model_sha256": digest(payload["model"]), "questions_used": payload["questions_used"],
                "effort_points_used": payload["effort_used"], "cost_used": payload.get("cost_used", "0.00"), "checks_used": payload.get("checks_used", 0),
                "certificate_ids": [item["id"] for item in payload["certificates"]], "business_verified": False}
            _seal(row, payload)
        if prepared["action"] == "create":
            validate(prepared["arguments"])
            payload = {"model": copy.deepcopy(prepared["arguments"]), "sources": {fact["id"]: _source(fact, time.time()) for fact in prepared["arguments"]["facts"]},
                       "questions_used": 0, "effort_used": 0, "pending": {}, "operations": {}, "certificates": [], "removed": False,
                       "reservation": {"operation": operation, "binding": digest(prepared)}}
            row = {"id": identifier, "actor": actor, "context": context, "schema": "lightwork.shared-decision-evidence.v1"}
            _seal(row, payload)
            guard()
            reserved = _reserve_create(row, payload, guard)
            def admit(current):
                guard()
                admitted = _open(current)
                if current.get("_audit_pending") or admitted.get("reservation") != payload["reservation"]:
                    raise HTTPException(409, "The original admission is unconfirmed. Read its original result; no model was repeated.")
                del admitted["reservation"]
                _complete(current, admitted)
                guard()
                _fresh_effect(prepared, None, admitted)
                checked_effect.update(before=None, after=admitted)
            STORE.update(identifier, admit, expected_revision=reserved["revision"], action="shared_decision_created", actor=actor,
                **_write_checks(payload["model"], physical_guard))
        else:
            STORE.update(identifier, effect, expected_revision=prepared["revision"], action="shared_decision_" + prepared["action"], actor=actor,
                **_write_checks(prepared["source_review"]["model"], physical_guard))
        return original(request, identifier, operation, binding=digest(prepared))


def _fresh_effect(prepared, before, after):
    """Repeat source/date checks after encryption and the native writer wait."""
    now, action = time.time(), prepared["action"]
    if action in {"create", "edit"} and any(case["due_at"] <= now for case in after["model"]["cases"]):
        raise HTTPException(409, "A reviewed decision deadline expired before the change could be recorded.")
    if action == "acquire" and _solver(before, now).acquisition()["selected"] != prepared["selection"]:
        raise HTTPException(409, "The reviewed observation expired or changed before budget reservation. Review it again.")
    if action == "acquire_batch" and _robust_current(before, now).get("batch") != prepared["selection"]:
        raise HTTPException(409, "The checked batch, source review or deadline expired before budget reservation. Check and review current information again.")
    if action == "answer":
        pending = before["pending"][prepared["arguments"]["request"]]
        source, solver = before["sources"][pending["fact"]], _solver(before, now)
        applicable = [case for case in pending["consent_cases"] if solver.source_current(pending["fact"], case)
            and any(row["id"] == case and now < row["due_at"] for row in before["model"]["cases"])]
        if not applicable or not source["observed_at"] <= now < source["expires_at"]:
            raise HTTPException(409, "The reviewed source or decision deadline expired before this report could be recorded. It remains unconfirmed.")
    if any(not check_certificate(item, after["model"], after["sources"], now) for item in after["certificates"]):
        raise HTTPException(409, "A dependent fact expired before certificate custody. Read current sources and review again.")


def _reserve_create(row, payload, guard):
    backend = STORE._backend()
    def admission_guard():
        guard()
        if any(case["due_at"] <= time.time() for case in payload["model"]["cases"]):
            raise HTTPException(409, "A decision deadline expired before the complete review could be admitted.")
    if isinstance(backend, LocalGovernedRecordBackend):
        with cross_process_lock(backend._store._dir() / ".namespace-admission", strict=True), cross_process_lock(backend._store._path(row["id"]), strict=True):
            guard()
            if any(case["due_at"] <= time.time() for case in payload["model"]["cases"]):
                raise HTTPException(409, "A decision deadline expired while waiting to save the complete review. Nothing was admitted.")
            return STORE.create(row, action="shared_decision_reserved", actor=row["actor"], max_records=100, effect_guard=admission_guard)
    if isinstance(backend, PostgresGovernedRecordBackend):
        return STORE.create(row, action="shared_decision_reserved", actor=row["actor"], max_records=100, effect_guard=admission_guard)
    if "robust" in payload["model"]:
        raise HTTPException(409, "This installation cannot save the loss review with its required final checks. No loss review was admitted.")
    guard()
    return STORE.create(row, action="shared_decision_reserved", actor=row["actor"], max_records=100)


def _write_checks(model, guard):
    if isinstance(STORE._backend(), (LocalGovernedRecordBackend, PostgresGovernedRecordBackend)):
        return {"effect_guard": guard}
    if "robust" in model:
        raise HTTPException(409, "This installation cannot save the loss review with its required final checks. No loss review was changed.")
    return {}
