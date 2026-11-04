"""Native reviewed reuse of exact pure rule components on a retained real case."""
from __future__ import annotations

import copy
import secrets
import time

from fastapi import HTTPException, Response
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
)
from maverick.flow import runner, store
from maverick.flow import selective_qualification as engine
from maverick.governed_records import GovernedRecordStore

from . import local_flow_comparisons as cases
from . import local_flow_promotions as release
from .candidate_promotion_api import _binding

PAGE = "/learning/recheck-rules"
API = "/api/v1/learning/rule-requalification"
NOTICE = "Check your selected original case. Unchanged successful steps can reuse retained results; changed rules also receive a separate complete run with the same original values. Both runs count toward the displayed calculation time, which excludes saving results and browser time. This checks supported local rules without calling an AI service or connected tools. Publication stays a separate reviewed action; this result does not predict new work."


def records():
    release._records()
    return GovernedRecordStore("local-rule-requalification", "FRQ", "rule_requalification", required_backend="local")


def authority(request, context=None, *, write=False):
    tenant, owner, current = _binding(request, Response())
    if context is not None and current != context:
        raise HTTPException(409, "Your account, workspace or access changed. Private case details cannot be reused; refresh this page.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return tenant, owner, current


def _policy(request):
    from maverick.config import get_flows
    tenant, owner, context = authority(request)
    release._learning_allowed()
    flags = get_flows()
    return engine.digest([tenant, owner, context, release._owner_authority(tenant, owner),
        {key: flags.get(key) for key in ("enabled", "learned_operators", "composed_operators", "action_recipe_lineage", "max_seconds")}])


def _resolver(manifest):
    def resolve(identity):
        value = manifest.get(identity)
        return store.load_flow_snapshot(value) if value else None
    return resolve


def _current(request, flow_id):
    value = cases._current(request, flow_id, changed=False)
    tenant, owner, context, candidate, baseline, publication, root, bundle = value
    qualified = cases._domain(candidate)
    baseline_plan = engine.plan(baseline, publication.get("subflow_digests", {}), _resolver(publication.get("subflow_digests", {})))
    candidate_plan = engine.plan(candidate, qualified["manifest"], _resolver(qualified["manifest"]))
    if not baseline_plan or not baseline_plan[-1]["writes"]:
        raise HTTPException(409, "Give the published workflow a final named result before retaining case evidence.")
    return value, qualified, baseline_plan, candidate_plan


def listing(request, flow_id=""):
    tenant, owner, context = authority(request)
    flows = store.list_flow_summaries(owner=owner, bounded=True)
    if len(flows) > 100:
        raise HTTPException(409, "Choose this workflow from its saved page; the bounded picker supports one hundred workflows.")
    result = {"semantic_reuse_available": config.get_features().get("semantic_rule_reuse") is True, "context": context, "flows": [{"value": row["id"], "label": row["name"]} for row in flows], "notice": NOTICE}
    if flow_id:
        current, qualified, left, right = _current(request, flow_id)
        _tenant, _owner, _context, candidate, baseline, publication, _root, bundle = current
        native = store.list_run_metadata(flow_id=flow_id, owner=owner, limit=200)
        retained = records().list(limit=1001)
        if len(retained) > 1000:
            raise HTTPException(503, "The complete case collection exceeds its supported bound. Nothing was omitted; narrow or repair the collection before continuing.")
        evidence = [row for row in retained if row.get("owner") == owner and row.get("tenant") == tenant
            and row.get("flow_id") == flow_id and row.get("kind") == "retain"]
        result.update(name=candidate.name, version=candidate.version, baseline_version=baseline.version,
            changed=bundle != publication["release_digest"],
            practices=[{"value": row.run_id, "when": row.created, "state": row.status} for row in native
                if not row.dry_run and row.status in {runner.STATUS_COMPLETED, runner.STATUS_FAILED}
                and row.definition_digest == publication["definition_digest"] and row.release_id == publication["release_id"]],
            evidence=[{"value": row["id"], "when": row["created_at"], "state": row["state"], "available": row.get("reuse_allowed") is True} for row in evidence],
            changes=[{"label": row["label"], "changed": row["source"] != next((old["source"] for old in left if old["id"] == row["id"]), None),
                "dependencies": [next(item["label"] for item in right if item["id"] == identity) for identity in row["depends_on"]]} for row in right],
            included=[{"name": flow.name, "version": flow.version} for flow in qualified["flows"][1:]])
    authority(request, context)
    return result


def _owned(request, identifier):
    tenant, owner, context = authority(request)
    row = records().get(identifier)
    if row is None or row.get("tenant") != tenant or row.get("owner") != owner or row.get("context") != context:
        raise HTTPException(404, "This original rule check is unavailable to the current account and workspace.")
    return row


def _material(request, kind, flow_id, run_id="", evidence_id="", *, semantic_reuse=False):
    tenant, owner, context = authority(request)
    if type(semantic_reuse) is not bool:
        raise HTTPException(422, "Choose whether to check complete supported rule behavior.")
    if semantic_reuse:
        if kind == "withdraw" or config.get_features().get("semantic_rule_reuse") is not True:
            raise HTTPException(409, "Complete rule-behavior reuse is off or unavailable for withdrawal. Your original evidence is retained.")
    current, qualified, left, right = _current(request, flow_id)
    _tenant, _owner, _context, candidate, baseline, publication, root, bundle = current
    source = None
    if kind == "retain":
        source = cases._source(owner, baseline, publication, run_id, left[-1]["writes"][-1])
    else:
        evidence = _owned(request, evidence_id)
        if evidence.get("flow_id") != flow_id or evidence.get("kind") != "retain":
            raise HTTPException(409, "Choose component evidence for this exact workflow.")
        if kind == "recheck":
            if (evidence["state"] != "done" or evidence.get("reuse_allowed") is not True
                    or evidence.get("_audit_pending") or evidence["baseline"] != publication
                    or evidence["policy"] != _policy(request)):
                raise HTTPException(409, "This retained evidence no longer has current case-use permission, publication or policy. Retain a new complete case check first.")
            source = cases._source(owner, baseline, publication, evidence["case"]["run_id"], left[-1]["writes"][-1])
            if source["version"] != evidence["case"]["version"]:
                raise HTTPException(409, "The original real case changed. Retain evidence from a current real case.")
            if bundle == publication["release_digest"]:
                raise HTTPException(409, "The saved version is already published. Save changed rules before selective requalification.")
    return {"kind": kind, "flow_id": flow_id, "name": candidate.name, "tenant": tenant, "owner": owner, "context": context,
        "root": root, "bundle": bundle, "version": candidate.version, "flow_revision": candidate.revision,
        "candidate_manifest": qualified["manifest"], "baseline": publication, "case": source,
        "evidence": evidence_id, "evidence_revision": None if kind == "retain" else evidence["revision"],
        "policy": _policy(request), "components": left if kind == "retain" else right, "case_use": kind != "withdraw",
        **({"semantic_reuse": True} if semantic_reuse else {})}


def _display(value):
    if type(value) is bool:
        return "Yes" if value else "No"
    if value is None:
        return "No value"
    if type(value) is dict:
        return "\n".join(str(key).replace("_", " ") + ": " + _display(item) for key, item in value.items())
    if type(value) is list:
        return "\n".join(str(index + 1) + ". " + _display(item) for index, item in enumerate(value))
    return str(value)


def _source_review(flow, manifest, label):
    rows = [{"label": label, "after": flow.name + " · saved version " + str(flow.version)}]
    definitions = [flow, *[store.load_flow_snapshot(value) for value in manifest.values()]]
    for included in definitions:
        rows.append({"label": label + " · included source", "after": included.name + " · saved version " + str(included.version)})
        for node in included.nodes.values():
            title = included.name + " · " + (node.label or "Business step")
            if node.output:
                rows.append({"label": title + " · named result", "after": node.output.replace("_", " ")})
            if node.kind == "agent":
                artifact = node.learned_operator["artifact"]
                rows.append({"label": title + " · work", "after": node.brief})
                fields = []
                for name, declaration in artifact["spec"]["inputs"].items():
                    kind = declaration["type"]
                    bounds = "Whole number from " + str(declaration["min"]) + " to " + str(declaration["max"]) if kind == "integer" else "Text up to " + str(declaration["max_length"]) + " characters" if kind == "string" else "Yes or no"
                    fields.append(name.replace("_", " ") + ": " + bounds)
                rows.append({"label": title + " · named inputs", "after": "\n".join(fields)})
                rows.append({"label": title + " · fixed comparison values", "after": _display(artifact["spec"].get("constants", [])) or "No fixed comparison values"})
                rows.append({"label": title + " · taught examples", "after": "\n\n".join("Input values:\n" + _display(item["inputs"]) + "\nExpected answer: " + _display(item["output"]) for item in artifact["examples"])})
            elif node.kind == "setvar":
                rows.append({"label": title + " · business values", "after": _display(node.assignments)})
            elif node.kind == "subflow":
                rows.append({"label": title + " · included inputs", "after": _display(node.subflow_inputs)})
            elif node.kind in {"branch", "switch"}:
                rows.append({"label": title + " · route condition", "after": node.condition})
                def route(target, included=included):
                    return (included.nodes[target].label or "Business step") if target else "Finish this route"
                if node.kind == "branch":
                    rows.append({"label": title + " · routes", "after": "When true: " + route(node.if_true if node.if_true is not None else node.next) + "\nWhen false: " + route(node.if_false if node.if_false is not None else node.next)})
                else:
                    rows.append({"label": title + " · routes", "after": "\n".join("When " + _display(case.get("value")) + ": " + route(case.get("to") if case.get("to") is not None else node.next) for case in node.cases) + "\nOtherwise: " + route(node.next)})
    return rows


def prepare(request, kind, flow_id, run_id="", evidence_id="", *, context=None, semantic_reuse=False):
    authority(request, context)
    if kind not in {"retain", "recheck", "withdraw"}:
        raise HTTPException(422, "Choose a supported rule-check action.")
    with authority_effect_fence(), store._definitions_lock():
        value = _material(request, kind, flow_id, run_id, evidence_id, semantic_reuse=semantic_reuse)
        value["deadline"] = time.time() + 600
        changes = [{"label": "Workflow", "after": value["name"]}, {"label": "Published rules", "after": "Saved version " + str(value["baseline"]["definition_version"])},
            {"label": "Proposed saved rules", "after": "Saved version " + str(value["version"])},
            {"label": "Action", "after": "Retain a complete component check" if kind == "retain" else "Recheck affected components and independently rerun the complete rules" if kind == "recheck" else "Stop future reuse of this component evidence"}]
        if semantic_reuse:
            changes.append({"label": "Complete supported rule behavior", "after": "For eligible Yes/No or bounded whole-number rules, check every declared input combination (at most sixty-four per step). Complete matching behavior may reuse the prior known-case output even when its rule text changed. All checks and the separate complete workflow run count toward the existing fifteen-second and step allowance. Other steps use ordinary exact-source checks. No business action or future correctness is inferred."})
        if value["case"]:
            changes.extend({"label": "Original case · " + key.replace("_", " "), "after": _display(item)} for key, item in value["case"]["inputs"].items())
        changes.extend({"label": "Component " + str(index + 1), "after": item["label"] + " · reads " + (", ".join(name.replace("_", " ") for name in item["reads"]) or "fixed values")}
            for index, item in enumerate(value["components"]))
        if kind != "withdraw":
            changes.extend(_source_review(store.load_flow_snapshot(value["baseline"]["definition_digest"]), value["baseline"].get("subflow_digests", {}), "Published source"))
            if kind == "recheck":
                changes.extend(_source_review(store.load_flow_snapshot(value["root"]), value["candidate_manifest"], "Proposed source"))
        changes.append({"label": "Permission and scope", "after": "I authorize using the displayed original values for this exact local known-case evidence and its reuse while source, policy and permission remain current. Retained evidence can be withdrawn separately. " + NOTICE if kind != "withdraw" else "The original record remains historical. Future reuse stops; this does not erase original work or publish a workflow."})
        if len(changes) > 512 or len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "These complete source examples exceed the protected review limit. Choose a smaller taught-rule workflow or use its complete comparison; no unseen source can be approved here.")
        authority(request, value["context"])
        return value, changes


def _guard(request, value, *, deadline=True):
    authority(request, value["context"])
    if deadline and time.time() >= value["deadline"]:
        raise HTTPException(409, "This review expired before admission. Review current rules and case permission again.")
    fresh = _material(request, value["kind"], value["flow_id"], (value["case"] or {}).get("run_id", ""), value["evidence"], semantic_reuse=value.get("semantic_reuse", False))
    if fresh != {key: item for key, item in value.items() if key != "deadline"}:
        raise HTTPException(409, "The workflow, included rules, original case, policy or case-use permission changed. Review current choices again.")


def apply(request, value, operation):
    authority(request, value["context"], write=True)
    identifier = "FRQ-" + operation
    service = records()
    binding = engine.digest(value)
    with authority_effect_fence(), store._definitions_lock():
        existing = service.get(identifier)
        if existing is not None:
            if existing.get("binding") != binding or existing.get("owner") != value["owner"]:
                raise HTTPException(409, "This original request belongs to a different reviewed rule check.")
            return original(request, identifier)
        _guard(request, value)
        row = service.create({"id": identifier, **copy.deepcopy(value), "binding": binding,
            "state": "prepared", "reuse_allowed": False}, action="flow.requalification.reviewed", actor=value["owner"], max_records=1000)
        def claim(current):
            _guard(request, value)
            if current["state"] != "prepared" or current["binding"] != binding or current.get("_audit_pending"):
                raise HTTPException(409, "The original rule-check admission is uncertain. Read its original result without repeating it.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"], action="flow.requalification.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        if value["kind"] == "withdraw":
            target = _owned(request, value["evidence"])
            def withdraw(current):
                _guard(request, value)
                current["reuse_allowed"] = False
                current["withdrawn_by_request"] = identifier
            service.update(target["id"], withdraw, expected_revision=target["revision"], action="flow.requalification.withdraw", actor=value["owner"])
            result = {"withdrawn": True}
        else:
            budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
            selected = value["baseline"]["definition_digest"] if value["kind"] == "retain" else value["root"]
            manifest = value["baseline"].get("subflow_digests", {}) if value["kind"] == "retain" else value["candidate_manifest"]
            flow = store.load_flow_snapshot(selected)
            cached = None if value["kind"] == "retain" else _owned(request, value["evidence"])["result"]["selective"]["components"]
            def guard():
                _guard(request, value)
            selective = engine.evaluate(flow, manifest, value["case"]["inputs"], resolve=_resolver(manifest),
                guard=guard, budget=budget, original=identifier, evidence=cached, semantic_reuse=value.get("semantic_reuse", False))
            complete = engine.complete(flow, value["case"]["inputs"], resolve=_resolver(manifest), guard=guard, budget=budget, original=identifier)
            agreement = (selective["status"] == complete["status"] == runner.STATUS_COMPLETED
                and engine.digest(selective["data"]) == engine.digest(complete["data"]))
            result = {"selective": selective, "complete": complete, "agreement": agreement,
                "combined_calculation_ms": selective["elapsed_ms"] + complete["elapsed_ms"]}
        def finish(current):
            # Withdrawal changed its own target revision deliberately; the
            # completion receipt confirms that exact original accepted update.
            if value["kind"] == "withdraw":
                authority(request, value["context"])
                target = _owned(request, value["evidence"])
                if target.get("withdrawn_by_request") != identifier or target.get("reuse_allowed") is not False:
                    raise HTTPException(409, "This original withdrawal result is uncertain. Nothing will be repeated.")
            else:
                _guard(request, value)
            current.update(state="done", result=result, reuse_allowed=value["kind"] == "retain" and result["agreement"], finished_at=time.time())
        service.update(identifier, finish, expected_revision=row["revision"], action="flow.requalification.complete", actor=value["owner"])
    return original(request, identifier)


def original(request, identifier):
    row = _owned(request, identifier)
    result = row.get("result") or {}
    current = False
    try:
        _guard(request, {key: row[key] for key in ("kind", "flow_id", "name", "tenant", "owner", "context", "root", "bundle", "version", "flow_revision", "candidate_manifest", "baseline", "case", "evidence", "evidence_revision", "policy", "components", "case_use", "deadline") } | ({"semantic_reuse": True} if row.get("semantic_reuse") is True else {}), deadline=False)
        current = row.get("reuse_allowed") is True if row["kind"] == "retain" else True
    except (HTTPException, ValueError, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError):
        current = False
    confirmed = row["state"] == "done" and not row.get("_audit_pending")
    projection = {"id": identifier, "context": row["context"], "kind": row["kind"], "name": row["name"], "version": row["version"], "recorded": row["created_at"],
        "confirmed": confirmed, "current": current, "state": row["state"], "notice": NOTICE,
        "message": "The original complete local result was recorded. Nothing ran again." if confirmed else "The original request is retained without a confirmed complete result. It will not run again; review current sources before starting a separate check.",
        "reuse_allowed": row.get("reuse_allowed") is True, "result": {}}
    if confirmed:
        if row["kind"] == "withdraw":
            projection["result"] = {"withdrawn": result.get("withdrawn") is True}
        else:
            projection["result"] = {"agreement": result["agreement"], "selective_state": result["selective"]["status"], "complete_state": result["complete"]["status"],
                "reused": sum(item["reused"] for item in result["selective"]["components"]), "recalculated": sum(not item["reused"] for item in result["selective"]["components"]),
                "selective_native_steps": result["selective"]["native_steps"], "complete_native_steps": result["complete"]["native_steps"],
                "combined_calculation_ms": round(result["combined_calculation_ms"], 3), "components": [{"label": item["label"], "reused": item["reused"], "reason": item["reason"], "state": item["status"]} for item in result["selective"]["components"]]}
            if current:
                projection["result"].update(selective_result=_display(result["selective"]["data"]), complete_result=_display(result["complete"]["data"]))
    authority(request, row["context"])
    return projection


def history(request):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(503, "The complete original history exceeds its supported bound. Nothing was omitted; original results remain readable individually.")
    result = [{"value": row["id"], "name": row["name"], "kind": row["kind"], "when": row["created_at"], "state": row["state"]} for row in rows
        if row.get("tenant") == tenant and row.get("owner") == owner and row.get("context") == context]
    authority(request, context)
    return {"context": context, "choices": result}


def operation():
    return secrets.token_hex(16)
