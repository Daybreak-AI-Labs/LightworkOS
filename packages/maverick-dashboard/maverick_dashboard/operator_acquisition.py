"""Private owned teaching-question policies, current consent and exact originals."""
from __future__ import annotations

import contextlib
import copy
import hmac
import json
import math
import re
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.file_lock import cross_process_lock
from maverick.flow import Flow, runner, store
from maverick.flow import learned_operator as scalar
from maverick.flow import operator_acquisition as engine
from maverick.flow.evolve import attach_learned_operator
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from . import auth
from . import local_flow_promotions as release
from .draft_api import context_for

FEATURE, PAGE, API = "operational_competence_acquisition", "/learning/acquisition", "/api/v1/operator-acquisition"
STORE = GovernedRecordStore("operator-acquisition", "OAC", "operator_acquisition", required_backend="local")
TTL, PLAN_LIMIT, QUESTION_LIMIT, NATIVE_LIMIT = 600, 32, 32, 4096
NOTICE = "Plan questions for a saved taught step using every simple rule that fits its examples. Earlier active-effort reports can inform estimated question cost only with current permission. An answer or a local reference check is evidence within your entered rule and situations, not independent business truth. Complete checking and its reference work count toward the shared allowance. Nothing calls AI, runs connected actions, saves or publishes a flow. No faster learning or unfamiliar-work improvement is established."
ACTIONS = {"create": "Entered teaching-question review", "plan": "Planned complete teaching questions", "answer": "Recorded a reviewed answer",
    "test": "Asked the selected local reference", "qualify": "Checked every declared situation", "scope": "Reviewed source permission",
    "withdraw": "Withdrew future question use", "acknowledge": "Stopped waiting for an unknown original", "remove": "Removed current teaching-question review"}


def authority(request, context=None, *, historical=False):
    auth.require_permission(request, "operate")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(401, "Sign in to your owned teaching workflow.")
    current = context_for(request)
    if context is not None and not hmac.compare_digest(context, current):
        raise HTTPException(409, "Your account or workspace changed. Private teaching content cannot be reused.")
    if not historical:
        from .flows_api import _require_flows
        _require_flows()
        release._learning_allowed()
        if config.config_source_errors(include_tenant=True) or config.get_features().get(FEATURE) is not True:
            raise HTTPException(403, "Teaching-question planning is off. Earlier originals remain readable.")
    return actor, current


def _flow(request, flow_id):
    from .flows_api import _assert_flow_access, _require_learned_flow_evidence
    actor, _context = authority(request)
    flow = store.load_flow(flow_id)
    if flow is None or flow.owner != actor:
        raise HTTPException(404, "Choose a currently owned saved workflow.")
    _assert_flow_access(request, flow)
    _require_learned_flow_evidence(flow)
    return flow


def _base(request, flow_id, node_id):
    flow = _flow(request, flow_id)
    node = flow.nodes.get(node_id)
    if node is None or node.kind != "agent" or node.learned_operator is None or node.learned_operator["artifact"].get("schema") != scalar.SCHEMA:
        raise HTTPException(409, "Choose an attached saved simple teaching rule; combined rules need their existing Teach controls.")
    return {"flow": flow.to_dict(), "node": node_id, "artifact": copy.deepcopy(node.learned_operator["artifact"])}


def _reference(request, flow_id, output):
    actor, _context = authority(request)
    flow = release._current(current_tenant_id_strict(), actor, flow_id)
    published = store.load_published_bundle(flow_id)
    if published is None or published[0].owner != actor or published[0].to_dict() != flow.to_dict():
        raise HTTPException(409, "Choose current owned published rules with Use learned rules only enabled.")
    bundle = release.qualified_bundle(flow)
    if any(node.learned_operator is not None and node.learned_operator["artifact"].get("schema") != scalar.SCHEMA
            for definition in bundle["flows"] for node in definition.nodes.values()):
        raise HTTPException(422, "Choose published local rules built from simple taught examples. Other rule formats need their existing Teach controls; nothing was shortened or run.")
    if output not in {node.output for node in flow.nodes.values() if node.output}:
        raise HTTPException(422, "Choose an actual named result from the complete reference workflow.")
    return {"flow": flow.to_dict(), "output": output, "manifest": bundle["manifest"], "root": bundle["root"], "bundle": bundle["bundle_sha"],
        "included": [item.to_dict() for item in bundle["flows"][1:]], "publication": published[1],
        "authority": release._owner_authority(current_tenant_id_strict(), actor), "steps": 64}


@contextlib.contextmanager
def _writer(request, *, historical=False):
    with authority_effect_fence():
        authority(request, historical=historical)
        with store._definitions_lock():
            backend = STORE._backend()
            with cross_process_lock(backend._store._dir() / ".acquisition-admission", strict=True):
                yield


def _seal(row, payload):
    raw = json.dumps({"identity": [row["id"], row["actor"], row["context"], row["flow_id"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(raw.encode()) > 2000000:
        raise HTTPException(413, "The complete teaching record exceeds its supported bound. Nothing was shortened.")
    row["envelope"] = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Enable stored-data encryption before retaining private teaching evidence.")


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"], row["flow_id"]]:
        raise HTTPException(409, "The retained teaching owner could not be verified.")
    return value["payload"]


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    if type(identifier) is not str or re.fullmatch(r"OAC-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(404, "This teaching review is unavailable.")
    row = STORE.get(identifier)
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This teaching review is unavailable to your account and workspace.")
    return STORE._flush(row) if row.get("_audit_pending") else row


def _permission(arguments):
    if type(arguments.get("allowed")) is not bool or type(arguments.get("purpose")) is not str or not 10 <= len(arguments["purpose"].strip()) <= 2000:
        raise HTTPException(422, "Enter current source-use permission and its complete purpose.")
    expiry = arguments.get("expires_at")
    if type(expiry) not in {int, float} or not math.isfinite(expiry) or not time.time() < expiry <= time.time() + 30 * 86400:
        raise HTTPException(422, "Choose a future source review date within thirty days.")
    if type(arguments.get("allow_independent_artifact")) is not bool:
        raise HTTPException(422, "Choose explicitly whether this evidence may create a separately owned taught rule after another complete review.")


def _prior(request, identifier, budget):
    budget.check()
    row = _owned(request, identifier)
    payload = _open(row)
    fresh = _base(request, row["flow_id"], payload["node"])
    current = (not payload["removed"] and not payload["pending"] and payload["consent"] and time.time() < payload["settings"]["expires_at"]
        and payload["base"] == fresh and not row.get("_audit_pending"))
    observations = [item for item in payload["answers"] if current and item["allowed"] and time.time() < item["expires_at"]
        and payload["operations"][item["operation"]]["state"] == "confirmed"]
    return {"id": identifier, "revision": row["revision"], "current": current, "purpose": payload["settings"]["purpose"], "effort_unit": payload["settings"]["effort_unit"],
        "allow_independent_artifact": payload["settings"]["allow_independent_artifact"],
        "expires_at": payload["settings"]["expires_at"],
        "source": fresh, "observations": observations, "binding": digest(payload)}


def _source(request, flow_id, node_id, settings, budget):
    budget.check()
    source = {"base": _base(request, flow_id, node_id), "prior": [_prior(request, identifier, budget) for identifier in settings["prior"]]}
    if any(prior["effort_unit"] != settings["effort_unit"] for prior in source["prior"]):
        raise HTTPException(422, "Every selected earlier effort report must use your exact stated effort unit.")
    if sum(len(prior["observations"]) for prior in source["prior"]) > 128:
        raise HTTPException(422, "Choose at most one hundred twenty-eight complete earlier answered effort reports. None were omitted.")
    source["reference"] = _reference(request, settings["reference"], settings["output"]) if settings["reference"] else None
    budget.check()
    return source


def _reports(source):
    return [{"id": prior["id"] + "|" + row["operation"], "feature": row["feature"], "reported_effort": row["reported_effort"]}
        for prior in source["prior"] for row in prior["observations"]]


def _identity(actor, context, flow_id, node_id, base):
    return "OAC-" + digest([actor, context, flow_id, node_id, base])[:32]


def _settings(arguments):
    keys = {"node", "reference", "output", "prior", "default_effort", "effort_unit", "allowed", "purpose", "expires_at", "allow_independent_artifact"}
    if type(arguments) is not dict or set(arguments) != keys:
        raise HTTPException(422, "Enter every ordinary source, reference, effort and permission field.")
    _permission(arguments)
    if any(type(arguments[key]) is not str or len(arguments[key]) > 256 for key in ("node", "reference", "output")) or not arguments["node"]:
        raise HTTPException(422, "Select the saved taught step and optional published reference result.")
    if bool(arguments["reference"]) != bool(arguments["output"]):
        raise HTTPException(422, "Choose both the local reference and its result, or leave both unused.")
    if type(arguments["prior"]) is not list or len(arguments["prior"]) > 8 or len(set(arguments["prior"])) != len(arguments["prior"]):
        raise HTTPException(422, "Choose at most eight different owned prior teaching reviews.")
    if type(arguments["default_effort"]) is not int or not 1 <= arguments["default_effort"] <= 1000 or type(arguments["effort_unit"]) is not str or not 1 <= len(arguments["effort_unit"].strip()) <= 100:
        raise HTTPException(422, "Name one consistent effort unit and enter one to one thousand default points.")
    return copy.deepcopy(arguments)


def _arguments(action, arguments, payload):
    allowed = {"create": None, "plan": set(), "qualify": set(), "answer": {"answer", "reported_effort", "allowed", "purpose", "expires_at", "allow_independent_artifact"},
        "test": {"reported_effort", "allowed", "purpose", "expires_at", "allow_independent_artifact"}, "scope": {"allowed", "purpose", "expires_at", "reuse_recorded_answers", "allow_independent_artifact"},
        "withdraw": set(), "remove": set(), "acknowledge": {"acknowledge_unknown"}}
    if action not in allowed or type(arguments) is not dict or action != "create" and set(arguments) != allowed[action]:
        raise HTTPException(422, "Enter exactly the complete fields for this teaching action.")
    if action == "create":
        return _settings(arguments)
    if action in {"answer", "test", "scope"}:
        _permission(arguments)
    if action == "scope" and type(arguments["reuse_recorded_answers"]) is not bool:
        raise HTTPException(422, "Choose explicitly whether the entire displayed retained answer evidence may be used again.")
    if action in {"answer", "test"} and (type(arguments["reported_effort"]) is not int or not 1 <= arguments["reported_effort"] <= 1000):
        raise HTTPException(422, "Report active question effort in your stated unit, from one to one thousand points.")
    if action == "answer":
        kind = payload["artifact"]["spec"]["output_type"]
        raw = arguments["answer"]
        if type(raw) is not str or len(raw) > 1024:
            raise HTTPException(422, "Enter one complete answer using the saved answer kind.")
        if kind == "boolean":
            if raw not in {"true", "false"}:
                raise HTTPException(422, "Choose Yes or No.")
            output = raw == "true"
        elif kind == "integer":
            if re.fullmatch(r"-?(?:0|[1-9][0-9]{0,24})", raw) is None:
                raise HTTPException(422, "Enter an exact whole-number answer without an exponent or commas.")
            output = int(raw)
        else:
            output = raw
        scalar._scalar(output, kind, output=True)
        if not payload["policy"] or scalar._canonical(output) not in {row["answer"] for row in payload["policy"]["next"]["branches"]}:
            raise HTTPException(422, "That answer disagrees with every current retained rule. Correct examples in Teach before a new review.")
        arguments = {**arguments, "answer": output}
    if action == "acknowledge" and (arguments["acknowledge_unknown"] is not True or not payload["pending"]):
        raise HTTPException(409, "Acknowledge the original remains unknown and its prior allowance stays spent.")
    return copy.deepcopy(arguments)


def _counts(request, flow_id, node_id, budget):
    actor, context = authority(request)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete one-hundred-review custody bound is full. No retained history was omitted.")
    totals = {"plans": 0, "questions": 0, "native": 0}
    for row in rows:
        budget.check()
        payload = _open(row)
        if row["flow_id"] == flow_id and payload["node"] == node_id:
            for key in totals:
                totals[key] += payload["spent"][key]
    return totals, [row for row in rows if (row["actor"], row["context"]) == (actor, context)]


def _current(payload, source):
    return bool(payload and payload["consent"] and not payload["removed"] and not payload["pending"]
        and time.time() < payload["settings"]["expires_at"] and payload["base"] == source["base"]
        and all(item["allowed"] and time.time() < item["expires_at"] for item in payload["answers"]))


def _management_source(row):
    return {"management": True, "custody": {key: row[key] for key in ("id", "actor", "context")}}


def prepare(request, flow_id, identifier, action, arguments):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    management = action in {"withdraw", "remove", "acknowledge"}
    with _writer(request, historical=management):
        actor, context = authority(request, historical=management)
        row = _owned(request, identifier, historical=management) if identifier else None
        payload = _open(row) if row else None
        if (action == "create") != (row is None) or row and row["flow_id"] != flow_id:
            raise HTTPException(409, "Choose this workflow's retained review or create its first review for the step.")
        arguments = _arguments(action, arguments, payload)
        settings = arguments if action == "create" else payload["settings"]
        node_id = settings["node"]
        if payload and (payload["removed"] and not management or payload["pending"] and not management):
            raise HTTPException(409, "Read the unknown original and review stopping its wait before a separate intent.")
        source = _management_source(row) if management else _source(request, flow_id, node_id, settings, budget)
        if action == "create":
            identifier = _identity(actor, context, flow_id, node_id, source["base"])
            if STORE.get(identifier):
                raise HTTPException(409, "This exact saved step already has a retained review. Open it; removal cannot reset its originals or shared allowance.")
        if not management:
            engine.domain(source["base"]["artifact"], budget)
        if payload and action in {"plan", "answer", "test", "qualify"} and not _current(payload, source):
            raise HTTPException(409, "The exact source or answer-use permission changed or expired. No earlier policy can be used.")
        if action in {"answer", "test", "qualify"} and (not payload["policy"] or payload["policy_binding"] != digest(source)):
            raise HTTPException(409, "Plan the complete current questions first. Changed prior consent invalidates earlier plans.")
        if action in {"answer", "test"} and payload["policy"]["next"]["question"] is None:
            raise HTTPException(409, "No distinguishing question remains in the complete declared situations.")
        if action in {"test", "qualify"} and source["reference"] is None:
            raise HTTPException(409, "Choose a current owned published local reference before native checking.")
        if action == "qualify" and payload["policy"]["status"] != "qualified":
            raise HTTPException(409, "Reviewed answers must establish complete agreement before the independent full check.")
        spent = copy.deepcopy(payload["spent"]) if management else _counts(request, flow_id, node_id, budget)[0]
        claims = {"plans": int(action == "plan"), "questions": int(action in {"answer", "test"}), "native": 0}
        if action in {"test", "qualify"}:
            claims["native"] = source["reference"]["steps"] * (1 if action == "test" else len(payload["policy"]["domain"])) + (len(payload["policy"]["domain"]) if action == "qualify" else 0)
        if any(spent[key] + claims[key] > limit for key, limit in (("plans", PLAN_LIMIT), ("questions", QUESTION_LIMIT), ("native", NATIVE_LIMIT))):
            raise HTTPException(409, "The shared lifetime teaching allowance is exhausted. No replacement, removal or unknown wait refunds it.")
        return {"id": identifier, "actor": actor, "context": context, "flow_id": flow_id, "node": node_id,
            "action": action, "arguments": arguments, "source": source, "revision": row["revision"] if row else None,
            "before": digest(payload), "current": payload, "claims": claims, "spent": spent, "expires": time.time() + TTL}


def _guard(request, prepared, budget):
    management = prepared["action"] in {"withdraw", "remove", "acknowledge"}
    authority(request, prepared["context"], historical=management)
    budget.check()
    if time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired while waiting for the native writer.")
    settings = prepared["arguments"] if prepared["action"] == "create" else prepared["current"]["settings"]
    source = (_management_source(_owned(request, prepared["id"], historical=True)) if management
        else _source(request, prepared["flow_id"], prepared["node"], settings, budget))
    if source != prepared["source"]:
        raise HTTPException(409, "The source, publication, prior answer permission or its exact meaning changed. Review current information.")
    if prepared["action"] in {"create", "scope", "answer", "test"}:
        _permission(prepared["arguments"])
    if prepared["action"] in {"plan", "answer", "test", "qualify"} and not _current(prepared["current"], source):
        raise HTTPException(409, "Current teaching-source or answer permission is unavailable; the result stays unknown.")
    # Source custody reads may themselves wait; check admission after those reads.
    authority(request, prepared["context"], historical=management)
    budget.check()
    if time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired while reading current source custody.")
    return source


def _reserve(request, prepared, operation, budget):
    receipt = {"action": prepared["action"], "binding": digest(prepared), "actor": prepared["actor"], "context": prepared["context"],
        "state": "unconfirmed", "recorded_at": time.time(), "business_verified": False, "admitted": copy.deepcopy(prepared["claims"]),
        "spent": {key: (prepared["current"]["spent"][key] if prepared["current"] else 0) + amount for key, amount in prepared["claims"].items()}}
    if prepared["action"] == "create":
        row = {"id": prepared["id"], "actor": prepared["actor"], "context": prepared["context"], "flow_id": prepared["flow_id"], "schema": engine.SCHEMA}
        payload = {"settings": prepared["arguments"], "node": prepared["node"], "base": prepared["source"]["base"], "artifact": prepared["source"]["base"]["artifact"],
            "consent": False, "removed": False, "pending": operation, "spent": {"plans": 0, "questions": 0, "native": 0}, "answers": [],
            "policy": None, "policy_binding": None, "qualification": None, "operations": {operation: receipt}}
        _seal(row, payload)
        backend = STORE._backend()
        with cross_process_lock(backend._store._dir() / ".namespace-admission", strict=True), cross_process_lock(backend._store._path(row["id"]), strict=True):
            _guard(request, prepared, budget)
            return STORE.create(row, action="acquisition_reserved", actor=prepared["actor"], max_records=100)
    def reserve(row):
        _guard(request, prepared, budget)
        payload = _open(row)
        if digest(payload) != prepared["before"] or row.get("_audit_pending") or len(payload["operations"]) >= 200:
            raise HTTPException(409, "The exact original state changed or its complete custody is full.")
        for key, amount in prepared["claims"].items():
            payload["spent"][key] += amount
        payload.update(pending=operation, policy=None, qualification=None)
        payload["operations"][operation] = receipt
        _seal(row, payload)
        _guard(request, prepared, budget)
    return STORE.update(prepared["id"], reserve, expected_revision=prepared["revision"], action="acquisition_reserved", actor=prepared["actor"])


def _run(flow, data, output, manifest, *, guard, budget, operation):
    steps = [0]
    def observe(*_args):
        guard()
        budget.check()
        steps[0] += 1
        if steps[0] > 64:
            raise ValueError("The complete owned reference exceeded sixty-four native steps.")
    def refuse(*_args):
        raise ValueError("Teaching questions never call AI or connected actions.")
    def resolve(identity):
        return store.load_flow_snapshot(manifest[identity]) if identity in manifest else None
    guard()
    started = time.perf_counter()
    result = runner.run_flow(flow, data=copy.deepcopy(data), agent_fn=refuse, action_fn=refuse,
        resolve_flow=resolve, run_id=operation, on_node=observe)
    guard()
    budget.check()
    if result.status != runner.STATUS_COMPLETED or output not in result.data:
        raise ValueError("The whole local reference did not return its selected answer. No partial answer is accepted.")
    return {"answer": result.data[output], "native_steps": steps[0], "elapsed_ms": (time.perf_counter() - started) * 1000}


def _qualification(prepared, guard, budget, operation):
    payload, source = prepared["current"], prepared["source"]
    base = Flow.from_dict(source["base"]["flow"])
    taught = attach_learned_operator(base, prepared["node"], payload["artifact"])
    node = copy.deepcopy(taught.nodes[prepared["node"]])
    node.next = None
    node.learned_fallback = False
    unit = Flow(id=base.id, name=base.name, owner=base.owner, version=base.version, revision=base.revision, start=node.id, nodes={node.id: node})
    reference = source["reference"]
    rows = []
    for index, inputs in enumerate(payload["policy"]["domain"]):
        guard()
        budget.check()
        candidate = _run(unit, inputs, node.output, {}, guard=guard, budget=budget, operation=operation + ":candidate:" + str(index))
        checked = _run(Flow.from_dict(reference["flow"]), inputs, reference["output"], reference["manifest"], guard=guard, budget=budget, operation=operation + ":reference:" + str(index))
        rows.append({"inputs": inputs, "candidate": candidate, "reference": checked,
            "agree": type(candidate["answer"]) is type(checked["answer"]) and candidate["answer"] == checked["answer"]})
    return {"status": "qualified" if all(row["agree"] for row in rows) else "disagreement", "rows": rows,
        "meaning": "Complete agreement with the selected saved local reference in these declared situations only; no business truth or speed gain is established."}


def _work(prepared, guard, budget, operation):
    action, payload, source = prepared["action"], prepared["current"], prepared["source"]
    if action == "plan":
        return {"policy": engine.plan(payload["artifact"], _reports(source), default_effort=payload["settings"]["default_effort"], budget=budget)}
    if action == "qualify":
        return {"qualification": _qualification(prepared, guard, budget, operation)}
    if action in {"answer", "test"}:
        question = payload["policy"]["next"]
        checked = None
        if action == "test":
            reference = source["reference"]
            checked = _run(Flow.from_dict(reference["flow"]), question["inputs"], reference["output"], reference["manifest"], guard=guard, budget=budget, operation=operation)
            output = checked["answer"]
        else:
            output = prepared["arguments"]["answer"]
        artifact = engine.answer(payload["artifact"], question, output, budget=budget)
        return {"artifact": artifact, "observed": {"operation": operation, "inputs": question["inputs"], "answer": output,
            "feature": engine.feature(artifact["spec"], question["inputs"]), "reported_effort": prepared["arguments"]["reported_effort"],
            "allowed": prepared["arguments"]["allowed"], "purpose": prepared["arguments"]["purpose"], "expires_at": prepared["arguments"]["expires_at"],
            "allow_independent_artifact": prepared["arguments"]["allow_independent_artifact"],
            "recorded_at": time.time(), "quality": "local_reference_report" if checked else "operator_assertion", "native": checked}}
    return {}


def _finish(payload, prepared, operation, result):
    action = prepared["action"]
    if action == "create":
        payload["consent"] = prepared["arguments"]["allowed"]
    elif action == "plan":
        payload.update(policy=result["policy"], policy_binding=digest(prepared["source"]))
    elif action in {"answer", "test"}:
        payload["artifact"] = result["artifact"]
        payload["answers"].append(result["observed"])
    elif action == "qualify":
        payload["qualification"] = result["qualification"]
        payload.update(policy=prepared["current"]["policy"], policy_binding=digest(prepared["source"]))
    elif action == "scope":
        payload["settings"].update({key: prepared["arguments"][key] for key in ("allowed", "purpose", "expires_at", "allow_independent_artifact")})
        payload["consent"] = prepared["arguments"]["allowed"]
        for observation in payload["answers"]:
            observation["allowed"] = prepared["arguments"]["allowed"] and prepared["arguments"]["reuse_recorded_answers"]
            observation["allow_independent_artifact"] = observation["allowed"] and prepared["arguments"]["allow_independent_artifact"]
            if observation["allowed"]:
                observation.update(purpose=prepared["arguments"]["purpose"], expires_at=prepared["arguments"]["expires_at"],
                    renewed_grant={"actor": prepared["actor"], "operation": operation, "recorded_at": time.time()})
    elif action in {"withdraw", "remove"}:
        payload["consent"] = False
        payload["removed"] = action == "remove"
    held = prepared["current"]["pending"] if prepared["current"] else None
    if held and action in {"acknowledge", "withdraw", "remove"}:
        payload["operations"][held]["wait_acknowledged_by"] = operation
    payload["pending"] = None
    payload["operations"][operation].update(state="confirmed", spent=copy.deepcopy(payload["spent"]),
        status=result.get("qualification", {}).get("status", result.get("policy", {}).get("status", "recorded")))


def apply(request, prepared, operation):
    if type(operation) is not str or re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "An exact original request reference is required.")
    prior = recover(request, prepared, operation)
    if prior:
        return prior
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request, historical=prepared["action"] in {"withdraw", "remove", "acknowledge"}):
        prior = recover(request, prepared, operation)
        if prior:
            return prior
        _guard(request, prepared, budget)
        reserved = _reserve(request, prepared, operation, budget)
        if not reserved or reserved.get("_audit_pending"):
            return original(request, prepared["id"], operation)
        def guard():
            return _guard(request, prepared, budget)
        result = _work(prepared, guard, budget, operation)
        def finish(row):
            guard()
            payload = _open(row)
            if payload["pending"] != operation or row.get("_audit_pending"):
                raise HTTPException(409, "The original completion remains unknown; read it without repeating.")
            _finish(payload, prepared, operation, result)
            _seal(row, payload)
            guard()
        STORE.update(prepared["id"], finish, expected_revision=reserved["revision"], action="acquisition_" + prepared["action"], actor=prepared["actor"])
        return original(request, prepared["id"], operation)


def original(request, identifier, operation, *, binding=None):
    row = _owned(request, identifier, historical=True)
    receipt = _open(row)["operations"].get(operation)
    if receipt is None or binding is not None and receipt["binding"] != binding:
        raise HTTPException(404, "This exact original is unavailable.")
    authority(request, row["context"], historical=True)
    confirmed = receipt["state"] == "confirmed" and not row.get("_audit_pending")
    return {"context": row["context"], "id": identifier, "operation": operation, "confirmed": confirmed, "receipt": receipt,
        "message": "The exact original was recorded. Nothing ran or changed again." if confirmed else "The original remains unknown and will not repeat. Its admitted allowance stays spent."}


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
        raise HTTPException(409, "The complete original-history bound is exceeded; no entries were omitted.")
    choices = [{"value": row["id"] + "|" + operation, "label": ACTIONS[receipt["action"]] + " · " +
        ("Recorded result" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original unknown")}
        for row in rows if (row["actor"], row["context"]) == (actor, context) for operation, receipt in _open(row)["operations"].items()]
    authority(request, context, historical=True)
    return {"context": context, "choices": choices, "reviews": [{"value": row["id"], "flow": row["flow_id"], "label": "Earlier teaching review " + str(index + 1)}
        for index, row in enumerate(rows) if (row["actor"], row["context"]) == (actor, context)]}


def listing(request, flow_id=""):
    actor, context = authority(request)
    rows = store.list_flow_summaries(owner=actor, bounded=True)
    if len(rows) > 100:
        raise HTTPException(409, "The complete picker supports at most one hundred owned workflows. Nothing was omitted.")
    own = [row for row in STORE.list(limit=101) if (row["actor"], row["context"]) == (actor, context)]
    if len(own) > 100:
        raise HTTPException(409, "The complete retained teaching bound is full.")
    owned_ids = {row["id"] for row in rows}
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    references = []
    with _writer(request):
        for summary in rows:
            budget.check()
            try:
                # One owned flow that cannot be loaded or checked is left out of
                # the reference list; it must not take the whole picker with it.
                candidate = _flow(request, summary["id"])
                outputs = [{"value": node.output, "label": (node.label or "Taught step") + " answer"} for node in candidate.nodes.values() if node.output]
                if outputs:
                    _reference(request, candidate.id, outputs[0]["value"])
                    references.append({"value": candidate.id, "label": candidate.name, "outputs": outputs})
            except (ValueError, HTTPException) as exc:
                if isinstance(exc, HTTPException) and exc.status_code not in {404, 409, 422}:
                    raise
    result = {"context": context, "flows": [{"value": row["id"], "label": row["name"]} for row in rows], "references": references, "reviews": [
        {"value": row["id"], "label": (_open(row)["base"]["flow"]["name"] + " · " + (Flow.from_dict(_open(row)["base"]["flow"]).nodes[_open(row)["node"]].label or "Taught step"))
            if row["flow_id"] in owned_ids else "Earlier retained teaching review", "flow": row["flow_id"]} for row in own], "notice": NOTICE}
    if flow_id:
        flow = _flow(request, flow_id)
        result.update(flow=flow_id, name=flow.name, steps=[{"value": node.id, "label": node.label or "Taught step"} for node in flow.nodes.values()
            if node.kind == "agent" and node.learned_operator and node.learned_operator["artifact"].get("schema") == scalar.SCHEMA], binding=digest(flow.to_dict()))
    authority(request, context)
    return result


def view(request, identifier):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request):
        row = _owned(request, identifier)
        payload = _open(row)
        source = _source(request, row["flow_id"], payload["node"], payload["settings"], budget)
        current = _current(payload, source) and payload["policy_binding"] == digest(source)
        spent, _rows = _counts(request, row["flow_id"], payload["node"], budget)
        return {"context": row["context"], "id": identifier, "flow": row["flow_id"], "source": source,
            "settings": payload["settings"] if not payload["removed"] else None, "answers": payload["answers"] if not payload["removed"] else [],
            "current": current, "policy": payload["policy"] if current else None, "qualification": payload["qualification"] if current else None,
            "pending": payload["pending"], "removed": payload["removed"], "spent": spent, "limits": {"plans": PLAN_LIMIT, "questions": QUESTION_LIMIT, "native": NATIVE_LIMIT},
            "draft_ready": current and bool(payload["qualification"] and payload["qualification"]["status"] == "qualified"), "notice": NOTICE}


def _adoption_source(request, identifier, budget):
    row = _owned(request, identifier)
    payload = _open(row)
    source = _source(request, row["flow_id"], payload["node"], payload["settings"], budget)
    if (not _current(payload, source) or payload["policy_binding"] != digest(source)
            or not payload["qualification"] or payload["qualification"]["status"] != "qualified" or row.get("_audit_pending")):
        raise HTTPException(409, "A current complete reference check and source-use permission are required before opening an unsaved draft.")
    grants = [payload["settings"], *payload["answers"], *[prior for prior in source["prior"] if prior["observations"]],
        *[observation for prior in source["prior"] for observation in prior["observations"]]]
    if any(grant.get("allow_independent_artifact") is not True for grant in grants):
        raise HTTPException(409, "Every used example, answer and earlier effort report needs explicit current permission to create a separately owned taught rule.")
    if any(time.time() >= grant["expires_at"] for grant in grants):
        raise HTTPException(409, "A complete source or answer permission expired before separate acceptance.")
    authority(request, row["context"])
    budget.check()
    return row, payload, source


def _draft_value(request, identifier, budget):
    row, payload, source = _adoption_source(request, identifier, budget)
    result = attach_learned_operator(Flow.from_dict(payload["base"]["flow"]), payload["node"], payload["artifact"])
    authority(request, row["context"])
    budget.check()
    if not _current(payload, source):
        raise HTTPException(409, "The source or answer permission expired before the private draft was admitted.")
    review = changes({"action": "qualify", "source": source, "arguments": {}, "current": payload, "spent": payload["spent"],
        "claims": {"plans": 0, "questions": 0, "native": 0}})
    review.extend([{"label": "Every checked situation before separate acceptance", "after": _business(payload["qualification"])},
        {"label": "Separate acceptance and its purpose", "after": payload["settings"]["purpose"] + ". Saving accepts this as your independently owned taught rule. Later source-report withdrawal stops future question planning and does not remove this separately accepted saved rule. Its ordinary workflow controls apply. Publishing stays separate."},
        {"label": "Recorded resulting definition", "after": _business(result.to_dict())}])
    adoption_review = [{"label": item["label"], "value": str(item["after"])} for item in review]
    if len(adoption_review) > 1000 or len(json.dumps(adoption_review).encode()) > 6000000:
        raise HTTPException(413, "The entire adoption review exceeds its supported bound. Nothing was shortened.")
    _adoption_source(request, identifier, budget)
    return {"context": row["context"], "flow": result.to_dict(), "base": {key: payload["base"]["flow"][key] for key in ("id", "version", "revision")},
        "flow_json": json.dumps(result.to_dict(), allow_nan=False, separators=(",", ":")), "saved": False, "published": False,
        "adoption_review": adoption_review,
        "note": "Every declared situation agreed with your selected local reference. Review this private unsaved draft in Teach; saving and publishing stay separate."}


def draft(request, identifier):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request):
        return _draft_value(request, identifier, budget)


def save_acquired(request, identifier, acceptance, flow, save):
    """Explicit manual adoption uses the existing writer with fresh exact consent."""
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    if acceptance is not True:
        raise HTTPException(409, "Review and explicitly accept the entire independently owned taught rule before saving.")
    with _writer(request):
        value = _draft_value(request, identifier, budget)
        if flow.to_dict() != value["flow"]:
            raise HTTPException(409, "The complete acquired draft changed. Reopen its current source review before saving.")
        _adoption_source(request, identifier, budget)
        return save()


def author_handoff(request, flow_id, context=None, binding=None):
    with _writer(request):
        authority(request, context)
        value = listing(request, flow_id)
        if binding is not None and binding != value["binding"]:
            raise HTTPException(409, "The selected owned workflow changed before opening its complete form.")
        return {"context": value["context"], "flow": flow_id, "binding": value["binding"]}


def changes(prepared):
    source = prepared["source"]
    rows = [{"label": "Action", "after": ACTIONS[prepared["action"]]}, {"label": "Meaning and limit", "after": NOTICE}]
    if source.get("management"):
        return rows + [{"label": "Original custody only", "after": "This stops only your own retained teaching-review use or wait. No current workflow, source body, regrant or training is changed. Original unknown results and admitted allowance remain retained."},
            {"label": "Recorded source details", "after": _business({"custody": source["custody"], "operations": prepared["current"]["operations"], "spent": prepared["spent"]})}]
    # The selected step alone is used; show the whole saved flow separately.
    rows.append({"label": "Owned saved workflow and selected step", "after": source["base"]["flow"]["name"] + " · " + (Flow.from_dict(source["base"]["flow"]).nodes[source["base"]["node"]].label or "Taught step")})
    artifact = source["base"]["artifact"]
    arguments = copy.deepcopy(prepared["arguments"])
    if prepared["action"] == "create":
        arguments = _permission_review(arguments, source)
    rows.extend([{"label": "Every declared input and its complete limits", "after": _business(artifact["spec"])},
        {"label": "Every original taught calculation alternative", "after": "\n".join(_expression(program) for program in artifact["candidates"])},
        {"label": "Every original teaching example", "after": _business(artifact["examples"])},
        {"label": "Complete current change", "after": _business(arguments)}])
    if prepared["current"]:
        rows.extend([{"label": "Current source-use permission and purpose", "after": _business(_permission_review(prepared["current"]["settings"], source))},
            {"label": "Every retained answer and reported effort", "after": _business(prepared["current"]["answers"])},
            {"label": "Complete question plan", "after": _business(prepared["current"]["policy"])}])
        rows.append({"label": "Every remaining taught calculation alternative", "after": "\n".join(_expression(program) for program in prepared["current"]["artifact"]["candidates"])})
    for prior in source["prior"]:
        rows.append({"label": "Earlier effort report use and current permission", "after": _business({key: prior[key] for key in ("current", "purpose", "effort_unit", "expires_at", "allow_independent_artifact", "observations")})})
    if source["reference"]:
        ref = source["reference"]
        rows.append({"label": "Complete selected owned published local check rule", "after": _business(ref)})
        rows.append({"label": "Reference answer and declared meaning", "after": ref["output"] + "; local rule output is not independent business truth."})
    rows.append({"label": "Shared lifetime allowance", "after": _business({"already_spent": prepared["spent"], "admitted_by_this_intent": prepared["claims"],
        "limits": {"plans": PLAN_LIMIT, "questions": QUESTION_LIMIT, "native": NATIVE_LIMIT}, "unknown_or_remove": "No refund; a separate acknowledged intent is required after unknown completion."})})
    rows.append({"label": "Recorded source details", "after": _business(prepared)})
    if len(json.dumps(rows, allow_nan=False).encode()) > 6000000:
        raise HTTPException(413, "The entire review exceeds its display bound. No source may be confirmed unseen.")
    return rows


def _permission_review(settings, source):
    value = copy.deepcopy(settings)
    value["step_name"] = Flow.from_dict(source["base"]["flow"]).nodes[source["base"]["node"]].label or "Taught step"
    value["reference_name"] = source["reference"]["flow"]["name"] if source["reference"] else "No local check rule"
    if source["reference"]:
        reference = Flow.from_dict(source["reference"]["flow"])
        value["output"] = next((node.label or "Taught step") + " answer" for node in reference.nodes.values() if node.output == settings["output"])
    value["earlier_report_names"] = [prior["source"]["flow"]["name"] for prior in source["prior"]]
    for key in ("node", "reference", "prior"):
        value.pop(key, None)
    return value


def _business(value):
    """Complete ordinary values; identifiers and solver details stay in custody."""
    names = {"node": "Selected taught step", "reference": "Selected local check rule", "output": "Exact answer", "prior": "Selected earlier reports",
        "default_effort": "Default question effort", "effort_unit": "Shared effort unit", "allowed": "Current use permission", "purpose": "Exact use purpose",
        "expires_at": "Permission review date", "allow_independent_artifact": "Permit a separately accepted owned taught rule", "reuse_recorded_answers": "Permit every displayed retained answer again",
        "inputs": "Named question inputs", "output_type": "Answer kind", "constants": "Entered fixed values", "type": "Input kind", "min": "Smallest input", "max": "Largest input",
        "reported_effort": "Reported active effort", "recorded_at": "Recorded date", "quality": "Kind of evidence", "answer": "Exact answer", "native": "Actual local check",
        "native_steps": "Actual steps completed", "elapsed_ms": "Measured local calculation milliseconds", "agree": "Both answers agree", "candidate": "New taught rule answer",
        "domain": "Every entered situation", "behaviors": "Different complete possibilities",
        "question": "Question in the plan", "branches": "Every possible answer and next question", "remaining_behaviors": "Different complete possibilities remaining",
        "estimated_effort": "Estimated question effort", "estimated_remaining_effort": "Estimated remaining effort", "estimated_worst_effort": "Estimated most remaining effort",
        "cost_basis": "Why this estimated effort is used", "basis": "Stated basis", "outputs": "Complete answers in situation order", "multiplicity": "Matching taught rules",
        "status": "Current result", "rows": "Every checked situation", "meaning": "Meaning and limit", "observations": "Every permitted answered report",
        "plans": "Complete plans admitted", "questions": "Answers admitted", "already_spent": "Earlier lifetime admissions", "admitted_by_this_intent": "Admission for this change",
        "limits": "Shared lifetime limits", "unknown_or_remove": "Unknown results and removal", "qualification": "Complete local checking",
        "name": "Workflow name", "step_name": "Selected taught step", "reference_name": "Selected local check rule", "earlier_report_names": "Selected earlier reports", "kind": "Kind of step", "label": "Step name", "brief": "Work described for this step", "nodes": "Every entered step or future question",
        "flow": "Complete saved workflow", "source": "Complete selected sources", "base": "Original saved teaching source", "artifact": "Complete taught rule",
        "candidates": "Every calculation alternative", "program": "Calculation", "spec": "Entered input and answer limits", "examples": "Every teaching example",
        "learned_operator": "Rule matched to this work", "work_sha256": "Original work fingerprint", "schema": "Record format", "artifact_sha256": "Rule evidence fingerprint",
        "examples_sha256": "Teaching evidence fingerprint", "example_count": "Teaching examples retained", "comparison": "Complete effort comparison",
        "existing_complete_minimax_estimated_effort": "Estimated effort using the existing complete question planner", "strong_complete_same_information_effort": "Estimated effort using exhaustive comparison of the same information",
        "same_optimum": "Complete comparisons agree", "optimized_states": "Possible situations checked by the planner", "reference_states": "Possible situations checked independently",
        "start": "First step", "next": "Next question or step", "retries": "Allowed repeat attempts", "timeout": "Step time limit", "max_seconds": "Workflow time limit",
        "max_dollars": "Workflow spending limit", "max_concurrent": "Simultaneous workflow limit", "learned_fallback": "Allow other methods if the rule cannot answer",
        "notify": "Send workflow completion notice", "schedule": "Entered workflow schedule", "timezone": "Schedule time zone", "version": "Saved version",
        "owner": "Workflow owner", "actor": "Original signed-in owner", "context": "Account and workspace", "id": "Retained source reference", "node_id": "Step reference",
        "flow_id": "Saved workflow reference", "binding": "Exact source fingerprint", "revision": "Saved source generation", "policy_binding": "Question-source fingerprint",
        "before": "Earlier record fingerprint", "claims": "Allowance for this review", "spent": "Admitted allowance", "expires": "Complete review expires",
        "current": "Complete earlier evidence and current permission", "settings": "Source-use choices", "consent": "Source use permitted", "removed": "Current review removed",
        "pending": "Waiting for an original result", "operations": "Every retained original request", "operation": "Original request reference", "state": "Recorded check or result",
        "business_verified": "Independently verified business truth", "wait_acknowledged_by": "Separate acknowledgment retained",
        "policy": "Complete question plan", "renewed_grant": "New explicit permission", "reports": "Earlier effort reports", "feature": "Recorded effort grouping",
        "initial": "First question", "authority": "Current source-owner authority", "root": "Saved root fingerprint", "bundle": "Complete source fingerprint",
        "manifest": "Exact included workflow versions", "included": "Every included workflow", "publication": "Current published version", "steps": "Maximum local checking steps reserved"}
    meanings = {"boolean": "Yes or No", "integer": "Whole number", "text": "Text", "string": "Text", "operator_assertion": "Your reported answer", "local_reference_report": "Reported by your selected saved local rule",
        "qualified": "Every entered situation agrees", "questions_ready": "Questions remain", "disagreement": "Some entered answers disagree",
        "agent": "Taught calculation", "setvar": "Recorded calculation", "branch": "Choice between routes", "switch": "Choice among named routes", "subflow": "Included workflow",
        "confirmed": "Original result recorded", "unconfirmed": "Original completion remains unknown", "recorded": "Review recorded"}
    def render(item, indent="", field=""):
        if type(item) is list:
            if field == "candidates":
                return "\n".join(indent + _expression(program) for program in item)
            if field == "program":
                return indent + _expression(item)
            return "\n".join(indent + "Item " + str(index + 1) + ":\n" + render(child, indent + "  ") for index, child in enumerate(item)) or indent + "None"
        if type(item) is dict:
            return "\n".join(indent + names.get(key, "Retained evidence entry" if re.fullmatch(r"(?:OAC-)?[a-f0-9]{32,64}", key) else "Evidence fingerprint" if "sha" in key or "digest" in key else key.replace("_", " ").capitalize()) + ":\n" + render(child, indent + "  ", key)
                for key, child in item.items()) or indent + "None"
        if type(item) is bool:
            return indent + ("Yes" if item else "No")
        if item is None:
            return indent + "None"
        if field in {"expires_at", "recorded_at", "expires"} and type(item) in {int, float}:
            return indent + datetime.fromtimestamp(item, timezone.utc).isoformat()
        if type(item) is str and (field in {"id", "flow_id", "node", "reference", "context", "actor", "owner", "operation", "wait_acknowledged_by"}
                or (re.fullmatch(r"[a-f0-9]{32,64}", item) and ("sha" in field or "digest" in field or field in {"binding", "revision", "policy_binding", "before", "root", "bundle", "feature", "artifact"}))):
            return indent + ("Your signed-in account" if field in {"actor", "owner"} else "Exact reference retained in this original record")
        if field == "schema":
            return indent + "Complete saved calculation or teaching record, first format"
        return indent + meanings.get(item, str(item)) if type(item) is str else indent + str(item)
    return render(value)


def _expression(program):
    """Read the validated closed scalar grammar as an ordinary expression."""
    if type(program) is not list or not program or type(program[0]) is not str:
        return _business(program)
    operation, *arguments = program
    if operation == "field" and len(arguments) == 1:
        return str(arguments[0])
    if operation == "literal" and len(arguments) == 1:
        return "Yes" if arguments[0] is True else "No" if arguments[0] is False else json.dumps(arguments[0], ensure_ascii=False)
    symbols = {"add": "+", "sub": "−", "mul": "×", "eq": "=", "ne": "≠", "lt": "<", "le": "≤", "gt": ">", "ge": "≥", "and": "and", "or": "or", "concat": "followed by"}
    if operation in symbols and len(arguments) == 2:
        return "(" + _expression(arguments[0]) + " " + symbols[operation] + " " + _expression(arguments[1]) + ")"
    if operation == "not" and len(arguments) == 1:
        return "Not " + _expression(arguments[0])
    if operation == "if" and len(arguments) == 3:
        return "If " + _expression(arguments[0]) + ", answer " + _expression(arguments[1]) + "; otherwise " + _expression(arguments[2])
    operations = {"min": "Smaller value", "max": "Larger value", "strip": "Remove surrounding spaces", "lower": "Use lower case", "upper": "Use upper case"}
    return operations.get(operation, "Saved calculation") + " of " + ", ".join(_expression(item) for item in arguments)


def _answer_wire(value):
    if type(value) is bool:
        return {"kind": "boolean", "value": value}
    if type(value) is int:
        return {"kind": "integer", "text": str(value)}
    if type(value) is str:
        return {"kind": "text", "text": value}
    raise ValueError("A complete answer must retain its exact scalar kind.")


def public(value):
    """Exact answer kinds survive JSON; no rounded Number becomes evidence."""
    if type(value) is list:
        return [public(item) for item in value]
    if type(value) is int and abs(value) > 9007199254740991:
        return str(value)
    if type(value) is not dict:
        return value
    result = {}
    for key, item in value.items():
        if key == "answer":
            result[key] = _answer_wire(json.loads(item) if "state" in value and type(item) is str else item)
        elif key == "output" and "inputs" in value:
            result[key] = _answer_wire(item)
        elif key == "outputs" and "multiplicity" in value:
            result[key] = [_answer_wire(output) for output in item]
        elif key == "candidates":
            result[key] = [_program_wire(program) for program in item]
        elif key == "program":
            result[key] = _program_wire(item)
        else:
            result[key] = public(item)
    return result


def _program_wire(program):
    if type(program) is not list:
        return public(program)
    if len(program) == 2 and program[0] == "literal":
        return ["literal", _answer_wire(program[1])]
    return [_program_wire(item) if type(item) is list else public(item) for item in program]
