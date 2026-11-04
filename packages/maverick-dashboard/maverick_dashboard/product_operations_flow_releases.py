"""Native governed release decisions with reviewed Copilot operation and readback."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from functools import partial

from fastapi import HTTPException, Response
from maverick.governed_operations import digest
from pydantic import Field

from . import candidate_promotion_api as native
from . import local_flow_promotions as local
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class FlowChoice(StrictInput):
    flow: str = Field(min_length=1, max_length=128)
    practice: str = Field(default="", max_length=128)
    comparison: str = Field(default="", pattern=r"^(?:FCP-[a-f0-9]{32})?$")


class CandidateChoice(StrictInput):
    candidate: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ReviewChoice(CandidateChoice):
    approve: bool
    note: str = Field(min_length=1, max_length=1024)


def _call(function):
    return local._native_call(function)


def _plain_state(state):
    return {"awaiting_review": "Waiting for independent review", "authorized": "Approved for preparation",
            "staged": "Prepared for publication", "canary": "Published for a controlled trial",
            "active": "Published; execution check passed", "rolled_back": "Previous published rules restored",
            "denied": "Review declined", "uncertain": "Saved outcome needs checking"}.get(state, "Refresh the saved decision")


def _result_details(row):
    report = native._projection(row).get("local_release", {})
    comparison = dict(report.get("known_case_comparison", {"scope": "No known-case answer comparison was included."}))
    if "when" in comparison:
        comparison["recorded"] = datetime.fromtimestamp(comparison.pop("when"), timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    return {"result": _plain_state(row["state"]), "workflow": report.get("name", "Selected workflow"),
            "saved_version": report.get("version"), "published_baseline_version": report.get("baseline_version"),
            "actual_trial_runs": report.get("observed_runs", 0), "evidence_limit": report.get("evidence"),
            "known_case_comparison": comparison,
            "restore_behavior": report.get("rollback"),
            "open": {"label": "Open release decisions", "href": "/research#research-promotions"}}


def setup_snapshot(request, _selection, *, rules_only):
    value = _call(lambda: local.choices(request))
    flows = [row for row in value["flows"] if not row["root_rules_only"]] if rules_only else [
        row for row in value["flows"] if row["rules_only"] and row["published"] and row["practice_runs"]]
    fields = [{"name": "flow", "label": "Saved taught workflow", "kind": "select", "required": True,
               "choices": [{"value": row["id"], "label": row["name"] + " · version " + str(row["version"])} for row in flows]}]
    if not rules_only:
        fields.append({"name": "practice", "label": "Completed practice", "kind": "select", "required": True,
                       "depends_on": "flow", "choices_by": {row["id"]: [
                           {"value": run["id"], "label": row["name"] + " · saved version " + str(row["version"]) + " · practice " + str(index + 1)}
                           for index, run in enumerate(row["practice_runs"])] for row in flows},
                       "choices": [{"value": run["id"], "label": row["name"] + " · saved version " + str(row["version"]) + " · practice " + str(index + 1)}
                                   for row in flows for index, run in enumerate(row["practice_runs"])]})
        fields.append({"name": "comparison", "label": "Known-case comparison", "kind": "select", "required": False,
                       "depends_on": "flow", "choices_by": {row["id"]: [{"value": "", "label": "Readiness only; no answer comparison"}, *[
                           {"value": check["id"], "label": str(check["cases"]) + " selected known cases"} for check in row.get("comparisons", [])]] for row in flows},
                       "choices": [{"value": "", "label": "Readiness only; no answer comparison"}]})
    blocked = "No saved taught workflow is ready for this step. Open the native release preparation controls." if not flows else ""
    return Snapshot(digest([value["context"], flows]), "Current owned taught workflow versions and practice records",
                    "Save a draft that stops when learned rules cannot answer." if rules_only else
                    "Prepare exact-version execution-readiness evidence for independent approval. This does not establish accuracy or improvement.",
                    details={"saved_versions": [{"workflow": row["name"], "version": row["version"],
                                                  "published_baseline": row.get("baseline_version"),
                                                  "included_workflows": [{"workflow": child["name"], "version": child["version"],
                                                                           "uses_rules_only": child["rules_only"]}
                                                                          for child in row["included_workflows"]]} for row in flows]},
                    fields=fields, blocked=blocked)


def setup_prepare(request, selection, arguments, *, rules_only):
    setup_snapshot(request, selection, rules_only=rules_only)
    row = next((flow for flow in _call(lambda: local.choices(request))["flows"] if flow["id"] == arguments["flow"]), None)
    if (row is None or rules_only and row["root_rules_only"]
            or not rules_only and (not row["rules_only"] or not row["published"]
                                  or arguments["practice"] not in {run["id"] for run in row["practice_runs"]})):
        raise HTTPException(409, "Choose a current saved workflow and its own completed practice.")
    if arguments.get("comparison") and arguments["comparison"] not in {check["id"] for check in row.get("comparisons", [])}:
        raise HTTPException(409, "Choose a current known-case comparison for these exact saved and published rules.")
    return Preview("Save rule-only behavior as a new draft. Existing publication is unchanged." if rules_only else
                   "Authorize a current independent release administrator to publish only this exact reviewed version and restore its retained baseline. Share its instructions, teaching examples and any selected real-case inputs, expected answers and paired results for that exact review. No release is activated.",
                   changes=[{"label": "Workflow", "after": row["name"]},
                            {"label": "Saved version", "after": row["version"]},
                            {"label": "AI fallback", "after": "Stops when rules do not agree"},
                            *[{"label": "Included workflow", "after": child["name"] + " · version " + str(child["version"])
                               + (" · uses rules only" if child["rules_only"] else " · prepare its rules-only draft before release")}
                              for child in row["included_workflows"]]],
                   native={"flow": row["id"], "version": row["version"], "revision": row["revision"],
                           "bundle_sha": row["bundle_sha"],
                           "practice": arguments["practice"], "comparison": arguments.get("comparison", "")})


def setup_execute(request, _selection, arguments, prepared, _operation, *, rules_only):
    if (prepared.get("flow") != arguments["flow"] or prepared.get("practice") != arguments["practice"]
            or prepared.get("comparison", "") != arguments.get("comparison", "")):
        raise HTTPException(409, "The selected workflow or practice changed. Review again.")
    body = local.Selection(context=context_for(request), confirm=True, flow_id=arguments["flow"],
                           version=prepared["version"], revision=prepared["revision"], practice_run=arguments["practice"],
                           comparison_id=arguments.get("comparison", ""), bundle_sha=prepared["bundle_sha"])
    result = _call(lambda: local.prepare_local_release(request, body, rules_only=rules_only))
    return Outcome("confirmed", result["detail"], {"open": {"label": "Open saved release controls", "href": "/research#local-flow-release"}})


def setup_recover(request, _selection, arguments, prepared, _operation, *, rules_only):
    tenant, actor, _context = native._binding(request, Response())
    if not rules_only:
        try:
            record = local._target_record()
            if (record["tenant"] != tenant or record["owner"] != actor or record["flow_id"] != arguments["flow"]
                    or record["version"] != prepared["version"] or record["flow_revision"] != prepared["revision"]
                    or record["practice_run"] != arguments["practice"]
                    or record["bundle_sha"] != prepared["bundle_sha"]
                    or record.get("comparison_id", "") != arguments.get("comparison", "")):
                return None
            local._practice(record)
        except Exception:
            return None
        return Outcome("replayed", "The exact release-readiness review is already prepared. No release was activated.",
                       {"open": {"label": "Open release decisions", "href": "/research#research-promotions"}})
    flow = _call(lambda: local._current(tenant, actor, arguments["flow"]))
    if flow.version != prepared["version"] + 1 or flow.revision != prepared["revision"]:
        return None
    try:
        local.qualified_bundle(flow, permit_fallback=True)
        if any(node.learned_fallback is not False for node in flow.nodes.values() if node.kind == "agent"):
            return None
    except Exception:
        return None
    return Outcome("unconfirmed", "The current draft uses learned rules only. The original save reply remains unconfirmed; no action was repeated. Check the saved workflow before continuing.",
                   {"open": {"label": "Open saved workflow", "href": "/flows/designer/" + flow.id}})


def _state(request, *, administrator=False):
    tenant, actor, context = native._binding(request, Response(), administrator=administrator)
    service = native._service(request)
    rows = _call(lambda: service.list(tenant, actor, limit=256))
    return tenant, actor, context, service, rows


def proposal_snapshot(request, _selection):
    tenant, actor, context, _service, _rows = _state(request)
    try:
        record = local._target_record()
        local.run_admission(tenant, actor, record["run_id"])
        details = {"workflow": local.store.load_flow_snapshot(record["root"]).name,
                   "version": record["version"], "run": record["run_id"], "binding": record["binding"]}
    except Exception:
        return Snapshot(digest([tenant, actor, context, "not prepared"]), "Current local release readiness",
                        "Prepare a current exact-version practice review first.", blocked="No current release-readiness review is prepared for your account.")
    return Snapshot(digest([tenant, actor, context, details]), "Current exact-version practice and retained release",
                    "Ask another release administrator to review this exact workflow. Nothing is published now.",
                    details={"workflow": details["workflow"], "saved_version": details["version"]},
                    fields=[{"name": "candidate", "label": "Name for this release request", "kind": "text", "required": True}])


def proposal_prepare(request, selection, arguments):
    current = proposal_snapshot(request, selection)
    if current.blocked:
        raise HTTPException(409, current.blocked)
    tenant, actor, _context, _service, _rows = _state(request)
    record = local._target_record()
    local.run_admission(tenant, actor, record["run_id"])
    return Preview("Create an independent review request for this exact prepared workflow and practice evidence. Nothing is staged or published.",
                   changes=[{"label": "Request", "after": arguments["candidate"]},
                            {"label": "Workflow", "after": current.details["workflow"]},
                            {"label": "Saved version", "after": current.details["saved_version"]}],
                   native={"run": record["run_id"], "binding": record["binding"]})


def proposal_execute(request, _selection, arguments, prepared, _operation):
    tenant, actor, _context, service, _rows = _state(request)
    row = _call(lambda: service.request(tenant, actor, candidate_id=arguments["candidate"],
                                       run_id=prepared["run"], target_preset=local.TARGET))
    return Outcome("confirmed", "The exact workflow release is waiting for independent review. No publication changed.",
                   _result_details(row))


def proposal_recover(request, _selection, arguments, prepared, _operation):
    tenant, actor, _context, service, _rows = _state(request)
    try:
        row = service.inspect(tenant, actor, arguments["candidate"])
    except Exception:
        return None
    if row["requested_by"] != actor or row["manifest"]["run"]["run_id"] != prepared["run"]:
        return None
    return Outcome("replayed", "The exact release request is already recorded. Its creation was not repeated.",
                   _result_details(row))


def decisions_snapshot(request, _selection, *, action):
    tenant, actor, context, _service, rows = _state(request, administrator=action != "status")
    wanted = {"review": {"awaiting_review"}, "stage": {"authorized"}, "activate": {"staged"},
              "canary": {"canary"}, "rollback": {"canary", "active"}, "reconcile": {"uncertain"}}
    eligible = []
    details = []
    for row in rows:
        projected = native._projection(row)
        release = projected.get("local_release")
        if not release:
            continue
        if action != "status" and (row["state"] not in wanted[action] or actor in {row["requested_by"], row["candidate_principal"]}):
            continue
        if action == "canary" and not release.get("can_assess"):
            continue
        eligible.append(row)
        details.append({"request": row["candidate_id"], "state": _plain_state(row["state"]),
                        "workflow": release.get("name", "Selected workflow"), "version": release.get("version"),
                        "observed_runs": release.get("observed_runs", 0), "evidence": release.get("evidence")})
    fields = [] if action == "status" else [{"name": "candidate", "label": "Exact workflow release", "kind": "select", "required": True,
        "choices": [{"value": row["candidate_id"], "label": (native._projection(row).get("local_release", {}).get("name") or "Selected workflow") + " · " + row["candidate_id"]} for row in eligible]}]
    if action == "review":
        fields.extend([{"name": "approve", "label": "Approve this exact release", "kind": "boolean", "value": False},
                       {"name": "note", "label": "What you checked and any limits", "kind": "textarea", "required": True}])
    blocked = "No release is ready for this decision under your current authority. Assessing a trial requires an actual completed run of that exact publication." if action != "status" and not eligible else ""
    return Snapshot(digest([tenant, actor, context, [(row["candidate_id"], row["revision"]) for row in eligible], details]), "Current governed workflow releases and their actual publication results",
                    "Review current release evidence. Readiness and observed failure rate do not establish business improvement.",
                    details={"releases": details}, fields=fields, blocked=blocked)


def decision_prepare(request, _selection, arguments, *, action):
    tenant, actor, _context, service, _rows = _state(request, administrator=True)
    row = _call(lambda: service.inspect(tenant, actor, arguments["candidate"]))
    offered = decisions_snapshot(request, {}, action=action)
    if arguments["candidate"] not in {choice["value"] for choice in offered.fields[0]["choices"]}:
        raise HTTPException(409, "This exact release no longer offers that decision. Refresh before continuing.")
    report = _call(lambda: local.release_status(row["manifest"], review=True))
    notes = {"review": "Record independent review of this exact saved workflow. Approval does not activate it.",
             "stage": "Prepare this exact workflow and retain its previous compatible release.",
             "activate": "Publish this exact approved and prepared rule-only version. New runs will use these rules. The owner must finish a real run before its observed failure rate can be checked.",
             "canary": "Check actual finished runs from this publication. If its acceptance rules fail, Lightwork restores the retained previous rules. This does not establish answer accuracy or business improvement.",
             "rollback": report["rollback"], "reconcile": "Read the authoritative release and resolve the uncertain action without repeating it."}
    changes = [{"label": "Workflow release", "after": report["name"] + " · version " + str(report["version"])},
               {"label": "Evidence limit", "after": report["evidence"]}]
    if action == "review":
        changes.extend([{"label": "Your decision", "after": "Approve this exact release" if arguments["approve"] else "Do not approve this release"},
                        {"label": "Your review and limits", "after": arguments["note"]}])
    comparison = report.get("known_case_comparison")
    if comparison:
        changes.append({"label": "Known-case comparison limits", "after": comparison["scope"]})
        if comparison.get("reviewed_cases"):
            changes.append({"label": "Every selected real case", "after": [
                {"Inputs": "; ".join(name + ": " + str(value) for name, value in case["inputs"].items()),
                 "Expected final answer": case["expected"], "Published-rule answer": case["baseline"],
                 "Published rules match the expected answer": case["baseline_matched"],
                 "Proposed-rule answer": case["candidate"], "Proposed rules match the expected answer": case["candidate_matched"]}
                for case in comparison["reviewed_cases"]]})
    for step in report["steps"]:
        complete_step = {}
        for key, label in (("instructions", "Work instructions"), ("fallback", "When rules cannot answer"),
                           ("condition", "Condition"), ("output", "Result name"), ("next", "Next step"),
                           ("if_true", "When true"), ("if_false", "When false")):
            if step.get(key):
                complete_step[label] = step[key]
        questions = {}
        for name, limits in step.get("questions", {}).items():
            kind = {"integer": "Whole number", "string": "Text", "boolean": "Yes or no"}.get(limits["type"], "Value")
            if "min" in limits:
                kind += " from " + str(limits["min"]) + " to " + str(limits["max"])
            elif "max_length" in limits:
                kind += " up to " + str(limits["max_length"]) + " characters"
            questions[name] = kind
        if questions:
            complete_step["Every input and its limits"] = questions
        if step.get("examples"):
            complete_step["Every teaching example"] = [
                "; ".join(name + ": " + str(value) for name, value in example["inputs"].items()) + " → " + str(example["output"])
                for example in step["examples"]]
        if step.get("assignments"):
            complete_step["Every assigned value"] = {name: str(value) for name, value in step["assignments"].items()}
        if step.get("cases"):
            complete_step["Every route"] = [route["condition"] + " → " + route["next"] for route in step["cases"]]
        changes.append({"label": step["label"], "after": complete_step})
    return Preview(notes[action], changes=changes,
        native={"candidate": row["candidate_id"], "revision": row["revision"], "manifest": row["manifest_sha256"],
                "event_count": len(row["events"]), "action": action})


def decision_execute(request, _selection, arguments, prepared, _operation, *, action):
    tenant, actor, _context, service, _rows = _state(request, administrator=True)
    if prepared.get("candidate") != arguments["candidate"] or prepared.get("action") != action:
        raise HTTPException(409, "The reviewed release decision changed.")
    function = getattr(service, "assess_canary" if action == "canary" else action)
    extra = {}
    if action == "review":
        extra = {"approve": arguments["approve"], "reason_code": "reviewed_scope" if arguments["approve"] else "needs_revision",
                 "note": arguments["note"], "evidence_sha256": hashlib.sha256(arguments["note"].encode("utf-8")).hexdigest()}
    elif action == "rollback":
        extra = {"reason_code": "operator_requested"}
    result = _call(lambda: function(tenant, actor, arguments["candidate"], expected_revision=prepared["revision"], **extra))
    return Outcome("confirmed", "The release decision is recorded. " + _plain_state(result["state"]) + ".", _result_details(result))


def decision_recover(request, _selection, arguments, prepared, _operation, *, action):
    tenant, actor, _context, service, _rows = _state(request, administrator=True)
    row = _call(lambda: service.inspect(tenant, actor, arguments["candidate"]))
    if row["manifest_sha256"] != prepared["manifest"]:
        return None
    states = {"review": {"authorized", "denied"}, "stage": {"staged"}, "activate": {"canary"},
              "canary": {"active", "rolled_back"}, "rollback": {"rolled_back"}, "reconcile": {"canary", "rolled_back"}}
    events = row["events"][prepared["event_count"]:]
    if not any(event.get("actor") == actor and event.get("state") in states[action] for event in events):
        if row["state"] == "uncertain":
            return Outcome("unconfirmed", "The release outcome needs reconciliation. Inspect release decisions; no action was repeated.",
                           {"open": {"label": "Open release decisions", "href": "/research#research-promotions"}})
        return None
    return Outcome("replayed", "The reviewed release decision is already recorded. Its actual current result was refreshed; no action was repeated.",
                   _result_details(row))


def entries():
    common = {"family": "learning", "direct_ui": "/research#research-promotions", "pages": ("/research",)}
    result = []
    for rules_only, identifier, label in ((True, "rules_only", "Save learned-rule-only behavior"),
                                         (False, "release_prepare", "Prepare a taught workflow release review")):
        result.append(Adapter("learning." + identifier, label, input_model=FlowChoice,
            snapshot=partial(setup_snapshot, rules_only=rules_only), prepare=partial(setup_prepare, rules_only=rules_only),
            execute=partial(setup_execute, rules_only=rules_only), recover=partial(setup_recover, rules_only=rules_only),
            **{**common, "direct_ui": "/research#local-flow-release"}))
    result.append(Adapter("learning.release_status", "Check taught workflow release results", input_model=EmptyInput,
        snapshot=partial(decisions_snapshot, action="status"),
        prepare=lambda request, selection, _arguments: Preview("Current release results and their evidence limits.", native=decisions_snapshot(request, selection, action="status").details), **common))
    result.append(Adapter("learning.release_request", "Ask for independent taught workflow release approval", input_model=CandidateChoice,
        snapshot=proposal_snapshot, prepare=proposal_prepare, execute=proposal_execute, recover=proposal_recover, **common))
    for action, label in (("review", "Review an exact taught workflow release"), ("stage", "Prepare an approved taught workflow"),
                          ("activate", "Publish an approved taught workflow for a controlled trial"), ("canary", "Check actual trial runs of a taught workflow release"),
                          ("rollback", "Restore the retained taught workflow release"), ("reconcile", "Recover an uncertain taught workflow release")):
        result.append(Adapter("learning.release_" + action, label, input_model=ReviewChoice if action == "review" else CandidateChoice,
            snapshot=partial(decisions_snapshot, action=action), prepare=partial(decision_prepare, action=action),
            execute=partial(decision_execute, action=action), recover=partial(decision_recover, action=action), **common))
    return tuple(result)
