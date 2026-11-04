"""Owned executable rule/check-order evolution with exact native custody."""
from __future__ import annotations

import contextlib
import copy
import hmac
import json
import math
import re
import time
from pathlib import Path

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import cross_process_lock
from maverick.flow import Flow, runner, store
from maverick.flow import governed_rule_evolution as engine
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from . import auth
from . import local_flow_promotions as release
from .draft_api import context_for
from .operator_acquisition import _business

FEATURE, PAGE, API = "governed_rule_evolution", "/learning/rule-evolution", "/api/v1/governed-rule-evolution"
STORE = GovernedRecordStore("governed-rule-evolution", "GRE", "governed_rule_evolution", required_backend="local")
TTL = 600
LIMITS = {"builds": 8, "checks": 16, "native": 4096}
MANAGEMENT = {"withdraw", "remove", "acknowledge"}
ACTIONS = {"create": "Entered a rule review", "build": "Built and checked complete rule alternatives", "activate": "Accepted and published checked rules",
    "check": "Checked the active rules", "evaluator": "Accepted a complete checking order", "restore": "Restored the previous publication",
    "scope": "Reviewed source permission", "reconcile": "Accepted a separate current-state review", "withdraw": "Stopped future review use", "acknowledge": "Stopped waiting for an unknown original", "remove": "Removed current review"}
NOTICE = "Compare one owned taught rule in every possible situation within its saved input limits, then separately review which rules or checking order to use. The original rule supplies expected answers; agreement is not independently verified business truth. Checking input limits counts as real work. Equal or slower results remain visible. This runs locally without AI or connected actions and does not replace the app itself."


def authority(request, context=None, *, historical=False):
    auth.require_permission(request, "operate")
    actor, current = auth.caller_principal(request), context_for(request)
    if not actor:
        raise HTTPException(401, "Sign in to your own saved rules.")
    if context is not None and not hmac.compare_digest(context, current):
        raise HTTPException(409, "The account or workspace changed. Private rule contents cannot be reused.")
    if not historical:
        from .flows_api import _require_flows
        _require_flows()
        release._learning_allowed()
        if config.config_source_errors(include_tenant=True) or config.get_features().get(FEATURE) is not True:
            raise HTTPException(403, "Rule rewriting is off. Your protected earlier originals remain readable.")
    return actor, current


@contextlib.contextmanager
def _writer(request, flow_id, *, historical=False):
    with authority_effect_fence():
        authority(request, historical=historical)
        # Native publication/dispatch takes activation before definitions.
        with store._activation_lock(flow_id), store._definitions_lock():
            backend = STORE._backend()
            with cross_process_lock(backend._store._dir() / ".evolution-admission", strict=True):
                yield


def _seal(row, payload):
    raw = json.dumps({"identity": [row["id"], row["actor"], row["context"], row["flow_id"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(raw.encode()) > 6000000:
        raise HTTPException(413, "The complete evidence exceeds its supported storage bound. Nothing was shortened.")
    row["envelope"] = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Enable stored-data encryption before retaining private rule evidence.")


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"], row["flow_id"]]:
        raise HTTPException(409, "The retained rule owner could not be verified.")
    return value["payload"]


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    row = STORE.get(identifier) if type(identifier) is str and re.fullmatch(r"GRE-[a-f0-9]{32}", identifier) else None
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This rule review is unavailable to your account and workspace.")
    return STORE._flush(row) if row.get("_audit_pending") else row


def _flow(request, flow_id):
    from .flows_api import _assert_flow_access, _require_learned_flow_evidence
    actor, _context = authority(request)
    flow = store.load_flow(flow_id)
    if not flow or flow.owner != actor:
        raise HTTPException(404, "Choose a currently owned saved workflow.")
    _assert_flow_access(request, flow)
    _require_learned_flow_evidence(flow)
    return flow


def _harness():
    return digest([Path(module.__file__).read_bytes().hex() for module in (engine, runner)])


def _source(request, flow_id, payload, budget, *, observe_current=False):
    budget.check()
    flow = _flow(request, flow_id)
    published = store.load_published_bundle(flow_id)
    if not published or published[0].owner != flow.owner or published[0].revision != flow.revision:
        raise HTTPException(409, "Choose an owned published rule and keep its source available.")
    release.qualified_bundle(published[0], retained_manifest=published[1]["subflow_digests"], require_current_versions=False)
    if payload is None:
        if published[0].to_dict() != flow.to_dict():
            raise HTTPException(409, "Save and publish the same complete source before rewriting it.")
        values = engine.source(flow, budget)
        baseline = {"flow": flow.to_dict(), "publication": published[1], "values": values}
    else:
        baseline = payload["baseline"]
        expected = payload["expected"]
        if not observe_current and (flow.to_dict() != expected["flow"] or published[1] != expected["publication"]):
            raise HTTPException(409, "The complete saved draft or publication changed. No old check can be reused.")
        original = Flow.from_dict(baseline["flow"])
        if original.owner != flow.owner or original.revision != flow.revision:
            raise HTTPException(409, "The original workflow owner or saved generation changed.")
        engine.source(original, budget)
    result = {"baseline": baseline, "expected": {"flow": flow.to_dict(), "publication": published[1]},
        "authority": release._owner_authority(current_tenant_id_strict(), flow.owner), "harness": _harness()}
    budget.check()
    return result


def _permission(arguments):
    if (type(arguments.get("allowed")) is not bool or type(arguments.get("allow_independent_artifact")) is not bool
            or type(arguments.get("purpose")) is not str or not 10 <= len(arguments["purpose"].strip()) <= 2000):
        raise HTTPException(422, "Enter the complete current use purpose, permission and separate-artifact choice.")
    expiry = arguments.get("expires_at")
    if type(expiry) not in {int, float} or not math.isfinite(expiry) or not time.time() < expiry <= time.time() + 30 * 86400:
        raise HTTPException(422, "Choose a future permission review date within thirty days.")
    if type(arguments.get("time_limit_seconds")) is not int or arguments["time_limit_seconds"] not in {15, 60, 120}:
        raise HTTPException(422, "Choose the whole shared checking allowance: fifteen seconds, one minute or two minutes.")


def _arguments(action, arguments):
    expected = {"create": {"fault_limit", "allowed", "allow_independent_artifact", "purpose", "expires_at", "time_limit_seconds"},
        "scope": {"allowed", "allow_independent_artifact", "purpose", "expires_at", "time_limit_seconds"},
        "reconcile": {"allowed", "allow_independent_artifact", "purpose", "expires_at", "time_limit_seconds", "acknowledge_unknown"}, "activate": {"alternative", "independent_acceptance"},
        "evaluator": {"checking_order", "independent_acceptance"}, "acknowledge": {"acknowledge_unknown"}}
    if action not in ACTIONS or type(arguments) is not dict or set(arguments) != expected.get(action, set()):
        raise HTTPException(422, "Enter exactly the complete ordinary fields for this change.")
    if action in {"create", "scope", "reconcile"}:
        _permission(arguments)
    if action == "create" and (type(arguments["fault_limit"]) is not int or not 1 <= arguments["fault_limit"] <= engine.MAX_FAULTS):
        raise HTTPException(422, "Choose one to eight declared wrong-answer examples.")
    if action == "activate" and arguments["alternative"] not in {"tree", "direct"}:
        raise HTTPException(422, "Select an actual complete checked alternative.")
    if action == "evaluator" and arguments["checking_order"] not in {"ordinary", "evolved"}:
        raise HTTPException(422, "Choose the complete current or reordered checks.")
    if action in {"activate", "evaluator"} and arguments["independent_acceptance"] is not True:
        raise HTTPException(422, "Explicitly accept the entire independent change after its complete review.")
    if action in {"acknowledge", "reconcile"} and arguments["acknowledge_unknown"] is not True:
        raise HTTPException(422, "Acknowledge that the original remains unknown and its allowance stays spent.")
    return copy.deepcopy(arguments)


def _current(payload):
    return bool(payload and payload["consent"] and not payload["removed"] and not payload["pending"]
        and time.time() < payload["settings"]["expires_at"])


def _counts(flow_id, budget):
    result = dict.fromkeys(LIMITS, 0)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete retained rule-review custody is full.")
    for row in rows:
        budget.check()
        if row.get("flow_id") == flow_id:
            for key, value in _open(row)["spent"].items():
                result[key] += value
    return result


def _management(row):
    return {"management": True, "custody": {key: row[key] for key in ("id", "actor", "context")}}


def prepare(request, flow_id, identifier, action, arguments):
    budget = engine.local_budget()
    management = action in MANAGEMENT
    with _writer(request, flow_id, historical=management):
        actor, context = authority(request, historical=management)
        row = _owned(request, identifier, historical=management) if identifier else None
        payload = _open(row) if row else None
        if (action == "create") != (row is None) or row and row["flow_id"] != flow_id:
            raise HTTPException(409, "Choose this workflow's retained review or enter its first complete source.")
        arguments = _arguments(action, arguments)
        if payload and not management and (payload["removed"] or payload["pending"] and action != "reconcile"):
            raise HTTPException(409, "Read the original and separately review stopping its wait. Unknown work never repeats.")
        source = _management(row) if management else _source(request, flow_id, payload, budget, observe_current=action == "reconcile")
        if action == "create":
            if arguments["fault_limit"] > len(source["baseline"]["values"]):
                raise HTTPException(422, "Choose no more wrong-answer variants than the complete entered situations. Nothing was omitted.")
            identifier = "GRE-" + digest([actor, context, flow_id, source["baseline"]])[:32]
            if STORE.get(identifier):
                raise HTTPException(409, "This exact source already has retained custody. Removal cannot reset it.")
        if action in {"build", "activate", "check", "evaluator", "restore"} and not _current(payload):
            raise HTTPException(409, "Current source permission expired or was withdrawn. No old result is current.")
        if action in {"activate", "evaluator"}:
            _acceptance(payload, source, arguments, action)
        if action == "check" and (not payload["result"] or payload["result"]["status"] != "qualified"):
            raise HTTPException(409, "Build the complete current reference before checking active rules.")
        if action == "restore" and source["expected"]["publication"]["release_id"] == payload["baseline"]["publication"]["release_id"]:
            raise HTTPException(409, "The retained original publication is already active.")
        spent = copy.deepcopy(payload["spent"]) if management else _counts(flow_id, budget)
        claims = dict.fromkeys(LIMITS, 0)
        if action == "build":
            claims.update(builds=1, native=len(source["baseline"]["values"]) * (3 + payload["settings"]["fault_limit"]))
        if action == "check":
            claims.update(checks=1, native=len(source["baseline"]["values"]))
        if any(spent[key] + claims[key] > LIMITS[key] for key in LIMITS):
            raise HTTPException(409, "The shared lifetime work allowance is exhausted. Unknown work and removal never refund it.")
        budget.check()
        return {"id": identifier, "actor": actor, "context": context, "flow_id": flow_id, "action": action,
            "arguments": arguments, "source": source, "current": payload, "revision": row["revision"] if row else None,
            "before": digest(payload), "spent": spent, "claims": claims, "expires": time.time() + TTL}


def _acceptance(payload, source, arguments, action):
    if (not payload["settings"]["allow_independent_artifact"] or not payload["result"]
            or payload["result"]["source"] != digest({"baseline": source["baseline"], "harness": source["harness"]})
            or payload["result"]["status"] != "qualified"):
        raise HTTPException(409, "A complete current check and explicit permission to create an independently owned rule are required.")
    if action == "activate" and not any(item["key"] == arguments["alternative"] and item["qualified"] for item in payload["result"]["alternatives"]):
        raise HTTPException(409, "That complete alternative was not independently accepted on every situation.")


def _guard(request, prepared, budget):
    management = prepared["action"] in MANAGEMENT
    if authority(request, prepared["context"], historical=management)[0] != prepared["actor"]:
        raise HTTPException(403, "This exact review belongs to another signed-in owner.")
    budget.check()
    if time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired while waiting for current native custody.")
    row = _owned(request, prepared["id"], historical=management) if prepared["action"] != "create" else None
    source = _management(row) if management else _source(request, prepared["flow_id"], prepared["current"], budget, observe_current=prepared["action"] == "reconcile")
    if source != prepared["source"]:
        raise HTTPException(409, "The source, publication, authority or complete checking mechanism changed. Review it again.")
    if prepared["action"] in {"create", "scope", "reconcile"}:
        _permission(prepared["arguments"])
    elif not management and not _current(prepared["current"]):
        raise HTTPException(409, "Current source permission is unavailable; completion remains unknown.")
    if prepared["action"] in {"activate", "evaluator"}:
        _acceptance(prepared["current"], prepared["source"], prepared["arguments"], prepared["action"])
    authority(request, prepared["context"], historical=management)
    budget.check()
    if time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired during current-source reads.")
    if prepared["action"] in {"create", "scope", "reconcile"}:
        _permission(prepared["arguments"])
    elif not management and not _current(prepared["current"]):
        raise HTTPException(409, "Current source permission expired during physical custody preparation.")


def _reserve(request, prepared, operation, budget):
    receipt = {"action": prepared["action"], "binding": digest(prepared), "state": "unconfirmed", "actor": prepared["actor"],
        "context": prepared["context"], "recorded_at": time.time(), "admitted": prepared["claims"],
        "spent": {key: (prepared["current"]["spent"][key] if prepared["current"] else 0) + prepared["claims"][key] for key in LIMITS}}
    if prepared["action"] == "create":
        row = {"id": prepared["id"], "actor": prepared["actor"], "context": prepared["context"], "flow_id": prepared["flow_id"], "schema": engine.SCHEMA}
        payload = {"settings": prepared["arguments"], "baseline": prepared["source"]["baseline"], "expected": prepared["source"]["expected"],
            "consent": False, "removed": False, "pending": operation, "spent": dict.fromkeys(LIMITS, 0),
            "result": None, "active": None, "checking_order": "ordinary", "checker_epoch": 0, "operations": {operation: receipt}}
        _seal(row, payload)
        backend = STORE._backend()
        with cross_process_lock(backend._store._dir() / ".namespace-admission", strict=True), cross_process_lock(backend._store._path(row["id"]), strict=True):
            _guard(request, prepared, budget)
            return STORE.create(row, action="rule_evolution_reserved", actor=prepared["actor"], max_records=100)
    def mutate(row):
        _guard(request, prepared, budget)
        payload = _open(row)
        if digest(payload) != prepared["before"] or row.get("_audit_pending") or len(payload["operations"]) >= 200:
            raise HTTPException(409, "The exact earlier state changed or its complete original custody is full.")
        for key in LIMITS:
            payload["spent"][key] += prepared["claims"][key]
        payload["pending"] = operation
        payload["operations"][operation] = receipt
        if prepared["action"] == "build":
            payload["result"] = None
        if prepared["action"] in {"build", "check", "activate", "restore", "evaluator", "scope", "reconcile", "withdraw", "remove"}:
            payload.pop("last_check", None)
        _seal(row, payload)
        _guard(request, prepared, budget)
    return STORE.update(prepared["id"], mutate, expected_revision=prepared["revision"], action="rule_evolution_reserved", actor=prepared["actor"])


def _run(flow, inputs, answer_name, guard, budget):
    work = [0]
    def observe(_node, state, _outcome):
        guard()
        budget.check()
        work[0] += 1
        if work[0] > 64:
            raise ValueError("The entire local rule run exceeded sixty-four native steps.")
    def refuse(*_args, **_kwargs):
        raise ValueError("This check never calls AI, connected actions or additional workflows.")
    guard()
    started = time.perf_counter()
    run = runner.run_flow(flow, data=copy.deepcopy(inputs), agent_fn=refuse, action_fn=refuse, on_node=observe)
    guard()
    if run.status != runner.STATUS_COMPLETED or answer_name not in run.data:
        raise ValueError("A complete native answer is unavailable; no passing score can be invented.")
    value = run.data[answer_name]
    return {"answer": value, "native_steps": work[0], "elapsed_ms": (time.perf_counter() - started) * 1000}


def _build(request, prepared, budget):
    baseline = prepared["source"]["baseline"]
    flow, values = Flow.from_dict(baseline["flow"]), baseline["values"]
    answer_name = flow.nodes[flow.start].output
    def guard():
        _guard(request, prepared, budget)
    reference = [_run(flow, inputs, answer_name, guard, budget) for inputs in values]
    outputs = [item["answer"] for item in reference]
    indexed = engine.indexed_reference(values, outputs, budget)
    alternatives = engine.alternatives(flow, values, outputs, budget)
    for item in alternatives:
        runs = [_run(Flow.from_dict(item["flow"]), inputs, answer_name, guard, budget) for inputs in values]
        item["runs"] = runs
        item["qualified"] = all(engine.key(actual["answer"]) == engine.key(expected)
            and engine.exact(actual["answer"]) == indexed[json.dumps(inputs, sort_keys=True, separators=(",", ":"))]
            for actual, expected, inputs in zip(runs, outputs, values, strict=True))
        item["work"] = {"reference_native_steps": sum(row["native_steps"] for row in reference), "candidate_native_steps": sum(row["native_steps"] for row in runs),
            "includes_input_guard": True, "wall_time_is_measured_not_a_speed_claim": True}
    variants = engine.faults(flow, values, outputs, prepared["current"]["settings"]["fault_limit"], budget)
    mismatches = []
    for variant in variants:
        runs = [_run(Flow.from_dict(variant["flow"]), inputs, answer_name, guard, budget) for inputs in values]
        variant["runs"] = runs
        failed = [engine.key(actual["answer"]) != engine.key(expected) for actual, expected in zip(runs, outputs, strict=True)]
        variant["mismatches"] = failed
        mismatches.append(failed)
    ordering = engine.check_order(mismatches, len(values), budget)
    return {"status": "qualified" if all(item["qualified"] for item in alternatives) else "disagreement",
        "source": digest({"baseline": baseline, "harness": prepared["source"]["harness"]}), "values": values, "reference": reference,
        "indexed_reference": indexed, "alternatives": alternatives, "variants": variants, "ordering": ordering,
        "meaning": "Actual complete native answers compared with the original fixed rule; entered rule agreement, not independent truth or superiority."}


def _check(request, prepared, budget):
    payload = prepared["current"]
    if not payload["result"]:
        raise HTTPException(409, "Build the current complete reference and alternatives first.")
    published = store.load_published_bundle(prepared["flow_id"])
    flow, values = published[0], payload["baseline"]["values"]
    output = Flow.from_dict(payload["baseline"]["flow"]).nodes[Flow.from_dict(payload["baseline"]["flow"]).start].output
    plan = payload["result"]["ordering"]
    order = plan["order"] if payload["checking_order"] == "evolved" else plan["ordinary_order"]
    if sorted(order) != list(range(len(values))):
        raise HTTPException(409, "The complete checking order is unavailable.")
    result = []
    for index in order:
        run = _run(flow, values[index], output, lambda: _guard(request, prepared, budget), budget)
        agree = engine.key(run["answer"]) == engine.key(payload["result"]["reference"][index]["answer"])
        result.append({"situation": index, "inputs": values[index], "run": run, "agrees": agree})
        if not agree:
            return {"status": "disagreement", "rows": result, "all_situations_checked": False}
    return {"status": "qualified", "rows": result, "all_situations_checked": True}


def _activate(request, prepared, operation, budget):
    payload = prepared["current"]
    item = next(row for row in payload["result"]["alternatives"] if row["key"] == prepared["arguments"]["alternative"])
    candidate = Flow.from_dict(item["flow"])
    current = Flow.from_dict(payload["expected"]["flow"])
    candidate.version, candidate.revision = current.version, current.revision
    _guard(request, prepared, budget)
    saved = store.save_flow(candidate, expected_version=current.version, expected_revision=current.revision,
        effect_guard=lambda: _guard(request, prepared, budget))
    # Both native locks are already held. Recheck after the physical save and
    # before publication; a custody gap remains unknown rather than repeated.
    staged = copy.deepcopy(prepared)
    staged["source"]["expected"]["flow"] = saved.to_dict()
    staged["current"]["expected"]["flow"] = saved.to_dict()
    _guard(request, staged, budget)
    release_value = store.publish_flow(saved.id, expected_version=saved.version, expected_revision=saved.revision,
        expected_release_id=payload["expected"]["publication"]["release_id"], activation_id=operation + operation,
        effect_guard=lambda: _guard(request, staged, budget))
    return {"expected": {"flow": saved.to_dict(), "publication": release_value}, "active": {"alternative": item["key"], "restored": False, "operation": operation}}


def _restore(request, prepared, operation, budget):
    payload = prepared["current"]
    current = Flow.from_dict(payload["expected"]["flow"])
    _guard(request, prepared, budget)
    release_value = store.restore_published_flow(current.id, payload["baseline"]["publication"], expected_release_id=payload["expected"]["publication"]["release_id"],
        expected_version=current.version, expected_revision=current.revision, activation_id=operation + operation,
        effect_guard=lambda: _guard(request, prepared, budget))
    return {"expected": {"flow": current.to_dict(), "publication": release_value}, "active": {"alternative": "baseline", "restored": True, "operation": operation}}


def _finish(request, prepared, reserved, operation, result, budget):
    def mutate(row):
        payload = _open(row)
        if payload["pending"] != operation:
            raise HTTPException(409, "The exact original reservation changed.")
        # Activation changes exactly the reviewed draft/publication. Its final
        # writer checks that full resulting state, not the old source snapshot.
        final = copy.deepcopy(prepared)
        if prepared["action"] in {"activate", "restore"}:
            final["current"]["expected"] = result["expected"]
            final["source"]["expected"] = result["expected"]
        _guard(request, final, budget)
        action = prepared["action"]
        if action == "create":
            payload["consent"] = prepared["arguments"]["allowed"]
        elif action == "build":
            payload["result"] = result
        elif action in {"activate", "restore"}:
            payload.update(result)
            if action == "restore":
                payload["checking_order"] = "ordinary"
                payload["checker_epoch"] += 1
        elif action == "evaluator":
            payload["checking_order"] = prepared["arguments"]["checking_order"]
            payload["checker_epoch"] += 1
        elif action in {"scope", "reconcile"}:
            payload["settings"].update(prepared["arguments"])
            payload["consent"] = prepared["arguments"]["allowed"]
            payload["result"] = None
            payload.pop("last_check", None)
            if action == "reconcile":
                payload["expected"] = prepared["source"]["expected"]
                payload["active"] = None
                payload["checking_order"] = "ordinary"
                payload["checker_epoch"] += 1
        elif action in {"withdraw", "remove"}:
            payload["consent"] = False
            payload["removed"] = action == "remove"
            payload["result"] = None
        if action == "check":
            payload["last_check"] = result
        receipt = payload["operations"][operation]
        receipt.update(state="confirmed", recorded_at=time.time(), status=result.get("status", "recorded"), checking_order=payload["checking_order"],
            checker_epoch=payload["checker_epoch"], spent=copy.deepcopy(payload["spent"]), independent_business_truth=False)
        payload["pending"] = None
        _seal(row, payload)
        _guard(request, final, budget)
    return STORE.update(prepared["id"], mutate, expected_revision=reserved["revision"], action="rule_evolution_" + prepared["action"], actor=prepared["actor"])


def recover(request, prepared, operation):
    row = _owned(request, prepared["id"], historical=True) if STORE.get(prepared["id"]) else None
    if not row:
        return None
    receipt = _open(row)["operations"].get(operation)
    if not receipt:
        return None
    if receipt["binding"] != digest(prepared) or (receipt["actor"], receipt["context"]) != authority(request, historical=True):
        raise HTTPException(409, "The original is bound to another complete review or account.")
    return original(request, prepared["id"], operation)


def apply(request, prepared, operation):
    if type(operation) is not str or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "Use one exact original request reference.")
    authority(request, prepared["context"], historical=True)
    recovered = recover(request, prepared, operation)
    if recovered:
        return recovered
    budget = engine.local_budget(prepared["current"]["settings"]["time_limit_seconds"] if prepared["action"] in {"build", "check"} else 15)
    with _writer(request, prepared["flow_id"], historical=prepared["action"] in MANAGEMENT):
        recovered = recover(request, prepared, operation)
        if recovered:
            return recovered
        _guard(request, prepared, budget)
        reserved = _reserve(request, prepared, operation, budget)
        action = prepared["action"]
        if action == "build":
            result = _build(request, prepared, budget)
        elif action == "check":
            result = _check(request, prepared, budget)
        elif action == "activate":
            result = _activate(request, prepared, operation, budget)
        elif action == "restore":
            result = _restore(request, prepared, operation, budget)
        else:
            result = {}
        _finish(request, prepared, reserved, operation, result, budget)
        return original(request, prepared["id"], operation)


def original(request, identifier, operation):
    row = _owned(request, identifier, historical=True)
    payload = _open(row)
    receipt = payload["operations"].get(operation)
    if not receipt or (receipt["actor"], receipt["context"]) != authority(request, historical=True):
        raise HTTPException(404, "This exact original is unavailable to your account and workspace.")
    confirmed = receipt["state"] == "confirmed" and not row.get("_audit_pending")
    return {"context": row["context"], "id": identifier, "operation": operation, "confirmed": confirmed, "receipt": receipt,
        "message": "The exact original result was recorded; nothing repeats." if confirmed else "The original completion remains unknown. Read current state and separately acknowledge any next intent. Its allowance remains spent; nothing repeats."}


def original_report(value):
    receipt = value["receipt"]
    rows = ["Reviewed change: " + ACTIONS[receipt["action"]],
        "Original status: " + ("Recorded original result" if value["confirmed"] else "Completion remains unknown"), value["message"],
        "Recorded date: " + _business({"recorded_at": receipt["recorded_at"]})]
    for key, label in (("admitted", "Allowance admitted for this exact request"), ("spent", "Retained lifetime allowance")):
        if key in receipt:
            rows.append(label + ":\n" + _plain(receipt[key]))
    if value["confirmed"]:
        rows.append("Recorded result: " + {"qualified": "Every entered situation agrees", "disagreement": "Some entered situations disagree", "recorded": "Reviewed change recorded"}.get(receipt["status"], "Reviewed change recorded"))
    return "\n".join(rows)


def history(request, *, budget=None):
    actor, context = authority(request, historical=True)
    budget = budget or engine.local_budget()
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete original history exceeds its retained bound. Nothing was omitted.")
    choices, reviews = [], []
    for row in rows:
        budget.check()
        if (row.get("actor"), row.get("context")) != (actor, context):
            continue
        payload = _open(row)
        flow = store.load_flow(row["flow_id"])
        name = flow.name if flow and flow.owner == actor else "Your earlier rule review"
        reviews.append({"value": row["id"], "label": name, "flow": row["flow_id"]})
        choices.extend({"value": row["id"] + "|" + operation, "label": name + " · " + ACTIONS[receipt["action"]] + " · " +
            ("Original recorded" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original remains unknown")} for operation, receipt in payload["operations"].items())
    authority(request, context, historical=True)
    budget.check()
    return {"context": context, "reviews": reviews, "choices": choices}


def listing(request, flow_id=""):
    budget = engine.local_budget()
    actor, context = authority(request)
    values = []
    retained = history(request, budget=budget)["reviews"]
    entered = {row["flow"] for row in retained}
    for flow in store.list_flows():
        budget.check()
        if flow.owner != actor:
            continue
        try:
            if flow.id not in entered:
                _source(request, flow.id, None, budget)
            else:
                _flow(request, flow.id)
        except (HTTPException, ValueError):
            continue
        values.append({"value": flow.id, "label": flow.name})
    result = {"context": context, "flows": values, "reviews": retained}
    if flow_id:
        flow = _flow(request, flow_id)
        result.update(binding=digest(flow.to_dict()), name=flow.name)
    authority(request, context)
    budget.check()
    return result


def author_handoff(request, flow_id, context=None, binding=None):
    actor, current = authority(request, context)
    flow = _flow(request, flow_id)
    value = {"context": current, "flow": flow_id, "binding": digest(flow.to_dict())}
    if binding is not None and not hmac.compare_digest(binding, value["binding"]):
        raise HTTPException(409, "The complete saved rule changed before its form opened.")
    if flow.owner != actor:
        raise HTTPException(404, "The complete form is unavailable.")
    return value


def view(request, identifier):
    budget = engine.local_budget()
    row = _owned(request, identifier)
    payload = _open(row)
    _flow(request, row["flow_id"])
    current = False
    try:
        _source(request, row["flow_id"], payload, budget)
        current = _current(payload)
    except (HTTPException, ValueError):
        pass
    value = {"context": row["context"], "id": identifier, "flow": row["flow_id"], "current": current,
        "pending": payload["pending"], "removed": payload["removed"], "spent": payload["spent"], "limits": LIMITS,
        "settings": payload["settings"], "baseline": payload["baseline"] if current else None,
        "result": payload["result"] if current else None, "active": payload["active"], "checking_order": payload["checking_order"],
        "checker_epoch": payload["checker_epoch"], "last_check": payload.get("last_check") if current else None, "notice": NOTICE}
    value["report"] = report(value)
    _flow(request, row["flow_id"])
    if _owned(request, identifier)["revision"] != row["revision"]:
        raise HTTPException(409, "This current review changed while its full information was being read.")
    if current:
        _source(request, row["flow_id"], payload, budget)
        if not _current(payload):
            raise HTTPException(409, "Source permission expired while the complete current result was being read.")
    budget.check()
    return value


def report(value):
    rows = [{"label": "Current review", "after": "Current source and permission are available." if value["current"] else "Earlier checks are not current. Review source changes, permission or any unknown original."},
        {"label": "Shared lifetime work allowance", "after": _plain({"spent": value["spent"], "limits": value["limits"]})},
        {"label": "Current source permission", "after": _plain(value["settings"])},
        {"label": "Complete checking order", "after": "Reordered known counterexamples followed by every remaining situation" if value["checking_order"] == "evolved" else "Every situation in entered order"}]
    if value["current"]:
        rows.extend([{"label": "Complete original rule and every entered situation", "after": _plain(value["baseline"])},
            {"label": "Every complete checked rule, wrong-answer example and checking comparison", "after": _plain(value["result"])},
            {"label": "Latest actual check of current published rules", "after": _plain(value["last_check"])}])
    return rows


def _plain(value):
    hidden = {"harness", "signature", "release_id", "definition_digest", "release_digest", "source", "manifest", "operation"}
    names = {"fault_limit": "Declared wrong-answer examples", "time_limit_seconds": "Shared total checking time allowance in seconds", "checking_order": "Complete check order", "checker_epoch": "Saved checking-plan version",
        "definition_revision": "Exact saved source identity", "definition_version": "Version published", "release_id": "Exact publication identity", "definition_digest": "Exact published content identity", "release_digest": "Exact complete publication identity", "published_at": "Publication recorded date", "subflow_digests": "Exact included workflows",
        "alternative": "Selected checked rule", "key": "Checked alternative", "tree": "Complete supported decision routes", "yes": "Route when the condition is met", "no": "Route otherwise",
        "if_true": "Route when the condition is met", "if_false": "Route otherwise", "assignments": "Exact values returned", "condition": "Question used for this route", "cases": "Every named situation and route", "to": "Following step", "indexed_reference": "Complete direct answer lookup",
        "native_steps": "Actual native rule steps including input guard", "builds": "Complete builds admitted", "checks": "Complete active checks admitted",
        "reference_native_steps": "Actual original rule steps", "candidate_native_steps": "Actual proposed rule steps including the guard",
        "includes_input_guard": "Strict input validation included", "wall_time_is_measured_not_a_speed_claim": "Measured time establishes no speed claim",
        "construction": "How these complete routes were made", "tree_nodes": "Steps in the smallest supported decision tree", "worst_tree_steps": "Most tree steps for an entered situation before the guard",
        "searched_states": "Complete route choices compared", "changed_situation": "Entered situation intentionally given a wrong answer", "mismatches": "Every difference from the original answer",
        "known_negative_first_failure_checks": "Checks before finding all the declared wrong answers with the proposed order",
        "ordinary_known_negative_first_failure_checks": "Checks before finding those same wrong answers in entered order",
        "strong_same_information_first_failure_checks": "Checks using complete independent comparison of those same wrong answers",
        "passing_program_checks": "Situations still required for a passing rule", "complete_situations": "Complete entered situations", "reference_agrees": "Independent complete comparison agrees",
        "independent_acceptance": "Explicit independent acceptance", "acknowledge_unknown": "Earlier original remains unknown and spent allowance is kept"}
    def clean(item, field="", routes=None):
        if type(item) is str and field in hidden | {"definition_revision"}:
            return "Exact retained source reference; no new permission is inferred"
        if type(item) is str and routes and field in {"start", "next", "if_true", "if_false", "to"}:
            return routes.get(item, "Finish")
        if type(item) is str and field == "condition":
            return item.replace(" == false", " is No").replace(" == true", " is Yes").replace(" <= ", " is at most ")
        if type(item) is str and field in {"key", "alternative"}:
            return {"tree": "Checked decision routes", "direct": "Direct choice for each entered situation"}.get(item, item)
        if type(item) is dict:
            if "nodes" in item and "start" in item:
                routes = {node["id"]: "Step " + str(index + 1) + " · " + (node.get("label") or "Entered step") for index, node in enumerate(item["nodes"])}
            if field == "indexed_reference":
                return [{"inputs": clean(json.loads(key), "inputs", routes), "answer": clean(child, "answer", routes)} for key, child in item.items()]
            return {names.get(key, key): clean(child, key, routes) for key, child in item.items()}
        if type(item) is list:
            if field == "nodes":
                return [{routes.get(child["id"], "Entered step"): clean(child, "", routes)} for child in item]
            return [clean(child, field, routes) for child in item]
        return item
    return _business(clean(value))


def changes(prepared):
    rows = [{"label": "Selected change", "after": ACTIONS[prepared["action"]]}, {"label": "Meaning and limits", "after": NOTICE}]
    if prepared["action"] in MANAGEMENT:
        rows.append({"label": "Original custody only", "after": "Stops this original owner's review or wait only. No inaccessible source body, permission renewal, new-parent work or separately accepted publication is changed."})
    else:
        rows.extend([{"label": "Complete original saved rule and every entered situation", "after": _plain(prepared["source"]["baseline"])},
            {"label": "Current complete draft and published rules", "after": _plain(prepared["source"]["expected"])},
            {"label": "Complete selected choices and source permission", "after": _plain(prepared["arguments"])}])
        if prepared["current"]:
            rows.append({"label": "Current source use permission and its expiry", "after": _plain(prepared["current"]["settings"])})
            if prepared["current"]["result"]:
                rows.append({"label": "Every checked alternative, entered wrong-answer example and complete checking order", "after": _plain(prepared["current"]["result"])})
        if prepared["action"] == "activate":
            rows.append({"label": "Separate owner publication acceptance", "after": "This is your separate acceptance of the complete check; it is not approval by another person. Replaces this exact owned workflow's saved draft and current published rules. Schedules and triggers use the new release. Existing waiting runs remain bound to their old release. This separately accepted rule has its own normal workflow controls; later withdrawal stops future evolution use. No business effect is undone by restoring prior rules."})
        if prepared["action"] == "restore":
            rows.append({"label": "Exact restoration", "after": "Restores the retained earlier published rules with a new authorization. Keeps the current saved draft, restores ordinary checking order and never revives old waiting runs or undoes earlier business actions."})
        if prepared["action"] == "reconcile":
            rows.append({"label": "Separate current-state acceptance", "after": "The earlier effect may already have changed these exact current rules. Its original remains unknown. This new complete source and permission review clears the hold for a separate intent, invalidates every earlier current check, and never refunds allowance or relabels original success."})
    rows.append({"label": "Shared lifetime allowance", "after": _plain({"already_spent": prepared["spent"], "admitted_by_this_intent": prepared["claims"], "limits": LIMITS, "unknown_or_remove": "No refund; unknown originals never repeat automatically."})})
    if len(json.dumps(rows, allow_nan=False).encode()) > 6000000 or len(rows) > 1000:
        raise HTTPException(413, "The entire review exceeds its display bound. Nothing may be confirmed unseen.")
    return rows


def public(value):
    if type(value) is list:
        return [public(item) for item in value]
    if type(value) is int and abs(value) > 9007199254740991:
        return str(value)
    if type(value) is not dict:
        return value
    return {key: engine.exact(item) if key == "answer" else [engine.exact(child) for child in item] if key == "outputs" else public(item) for key, item in value.items()}
