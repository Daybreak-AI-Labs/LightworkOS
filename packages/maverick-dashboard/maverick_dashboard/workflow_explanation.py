"""A readable, current explanation of one saved learned workflow or pinned run.

Source contents only come from the lineage and example services' authorized
current reads. A failed learning grant check never unlocks a historical package.
Publication, learning permission, execution approval and recorded results are
separate facts; this read does not grant authority to run anything.
"""
from __future__ import annotations

import time
from functools import partial
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from maverick.flow import Flow, recipe_flow, store
from maverick.governed_operations import digest

from . import api as native
from . import api_flow_action_episodes as episodes
from . import api_flow_recipe_lineage as lineage
from .identity_format import humanize_principal

router = APIRouter(prefix="/flows", tags=["workflow-explanation"])
asset_router = APIRouter()
_STATES = {"queued": "Waiting to start", "claimed": "Starting", "running": "Running",
           "resuming": "Continuing", "paused_approval": "Waiting for approval",
           "paused_delay": "Waiting", "paused_event": "Waiting for another app",
           "completed": "Finished", "failed": "Stopped with a problem", "rejected": "Rejected",
           "cancelled": "Cancelled", "budget_limited": "Spending limit reached",
           "indeterminate": "Needs checking in the connected app"}


def _link(flow_id, run_id=None, label="Open saved workflow"):
    path = ("/flows/" + quote(flow_id, safe="") + "/runs/" + quote(run_id, safe="") if run_id else
            "/flows/designer/" + quote(flow_id, safe=""))
    return {"href": path, "label": label}


def _learning_evidence(request, definition):
    result = {"status": "Not confirmed", "message": "No signed learning evidence is bound to this saved version.",
              "examples": [], "teaching_rounds": None, "allowed_until": None}
    try:
        native._require_learned_flow_evidence(definition)
        reference = definition.recipe_lineage
        if not reference:
            result["message"] = ("This is an older learned workflow without signed source records. "
                                 "Current settings allow its use, but its learning permissions cannot be established here. Rebuild it from current reviewed examples.")
            return result
        service, context = lineage._service(request)
        inspected = lineage._call(lambda: service.get(context, reference["id"], detail=True))
        if inspected.get("status") == "audit_pending":
            result["message"] = "The learning decision is still waiting for its required activity record. Its evidence is withheld."
            return result
        package = inspected.get("package")
        if inspected.get("current_eligibility") != "accepted" or not isinstance(package, dict):
            result["message"] = "The learning permission ended or its source records are no longer available. Rebuild from current allowed examples."
            return result
        if inspected.get("reference") != reference or package.get("artifact") != definition.learned_recipe:
            raise ValueError("saved workflow does not match its admitted evidence")
        result.update(status="Allowed at this check", message=(
            "The bound source examples passed their current ownership, review, learning-permission and signed-record checks. "
            "Those records attest to what Lightwork recorded; they do not prove the business judgment was correct."),
            allowed_until=package["use_until"], teaching_rounds=len(package["batches"]),
            source_scope="These examples cover every recorded teaching round for this saved procedure.")
        for number, bundle in enumerate(package["bundles"], 1):
            body = bundle["body"]
            source = body["source"]
            source_service, source_context = episodes._service(request, source["flow_id"])
            current = episodes._call(partial(source_service.get, source_context, source["flow_id"], source["run_id"]))
            source_definition = native.get_flow_endpoint(request, source["flow_id"])
            allowed = (current.get("status") == "accepted" and current.get("source_current") is True
                       and current.get("training_available") is True and current.get("audit_status") == "delivered")
            result["examples"].append({"title": f"Example {number} · {source_definition['name']}",
                "permission": "Allowed for learning" if allowed else "No longer allowed for learning",
                "reviewed_by": humanize_principal(body["review"]["reviewer"]).name,
                "allowed_until": body["grant"]["use_until"],
                "source_run": _link(source["flow_id"], source["run_id"], "Review example and its permission")})
            if not allowed:
                result.update(status="Not currently allowed", message="An example changed or its learning permission ended. Future learned actions must stop until current evidence is restored or the workflow is rebuilt.")
    except HTTPException as exc:
        result.update(status="Not confirmed", examples=[], allowed_until=None, teaching_rounds=None)
        result.pop("source_scope", None)
        result["message"] = ("Current learning evidence is unavailable to your account, or a source review or learning permission changed. "
                             "Source examples are withheld. Open Teach to rebuild from current allowed examples.")
        if exc.status_code == 409 and isinstance(exc.detail, str) and "signed examples" in exc.detail:
            result["message"] = exc.detail
    except (ValueError, TypeError, KeyError, LookupError, OSError):
        result.update(status="Not confirmed", examples=[], allowed_until=None, teaching_rounds=None, message=(
            "The saved learning evidence could not be confirmed. Source examples are withheld. Rebuild from current reviewed examples on Teach."))
        result.pop("source_scope", None)
    return result


def explain(request, flow_id, run_id=None):
    saved = native.get_flow_endpoint(request, flow_id)
    definition = Flow.from_dict(saved)
    run = None
    if run_id:
        run = native._load_owned_run(request, run_id)
        if run.flow_id != flow_id:
            raise HTTPException(404, "This run is not available for the selected workflow.")
        try:
            definition = store.load_flow_snapshot(run.definition_digest)
            native._assert_flow_access(request, definition)
            if definition.id != flow_id or definition.version != run.definition_version:
                raise ValueError("run version changed")
        except (store.FlowSnapshotError, OSError, ValueError) as exc:
            raise HTTPException(409, "The saved version used by this run could not be confirmed. Open its run progress before deciding what to do next.") from exc
    publication = {"status": "Not published", "message": "Saving a draft does not start work. Publish it separately when ready."}
    published_id = ""
    if saved["published"]:
        published = native.get_published_flow_endpoint(request, flow_id)
        published_id = published["release_id"]
        publication = {"status": "Published", "published_version": published["published_version"],
                       "message": ("The latest saved draft is the published version." if saved["revision"] == published["flow"]["revision"] and saved["version"] == published["published_version"] else
                                   "The published version differs from the latest saved draft. New starts use the published version.")}
    taught = [node for node in definition.nodes.values() if node.learned_operator is not None]
    result = {"name": definition.name, "is_learned": definition.learned_recipe is not None or bool(taught),
              "explained_version": definition.version,
              "basis": "The saved version pinned to this run" if run else "The latest saved draft",
              "publication": publication, "checked_at": time.time(),
              "open_workflow": _link(flow_id),
              "teach": {"href": "/flows/" + quote(flow_id, safe="") + "/teach", "label": "Review teaching and source examples"},
              "limits": ["This explanation does not start or approve work.",
                         "Each connected action still checks current permissions, connections and spending limits.",
                         "A finished run is a recorded software result. Confirm the business outcome in the connected service separately."]}
    if definition.learned_recipe is not None:
        result["learning"] = _learning_evidence(request, definition)
        try:
            recipe_flow.validate_flow(definition)
            result["action_approval"] = {"status": "Approval required before each learned action",
                                         "message": "This saved procedure retains its required action approvals. Learning permission is separate from permission to carry out an action."}
        except (ValueError, TypeError, KeyError):
            result["action_approval"] = {"status": "Approval structure not confirmed",
                                         "message": "The saved procedure does not match its reviewed action structure. Do not run it until it is rebuilt and reviewed."}
    elif taught:
        from maverick.flow.ir import validate_learned_operator

        from .flow_teach_ops_api import _rule_summary
        steps = []
        for number, node in enumerate(taught, 1):
            try:
                validate_learned_operator(node)
                summary = _rule_summary(node.learned_operator["artifact"])
                steps.append({"title": node.label or "Taught step " + str(number),
                              "status": "Saved taught rule confirmed", "example_count": summary["examples"]})
            except (ValueError, TypeError, KeyError):
                steps.append({"title": node.label or "Taught step " + str(number), "status": "Taught rule not confirmed"})
        result["learning"] = {"status": "Rules taught from entered examples", "examples": [], "taught_steps": steps,
                              "message": "These rules use examples entered on Teach. They do not have a signed source-run history or a separate learning-withdrawal decision. Review their examples and remove a rule on Teach when needed."}
        approvals = sum(node.kind == "approval" for node in definition.nodes.values())
        result["action_approval"] = {"status": str(approvals) + " saved approval steps",
                                     "message": "Review where the saved approval steps sit in the procedure. This count does not establish that every connected action requires approval."}
    if run:
        projected = native._run_out(run)
        actions = []
        for number, node in enumerate((node for node in definition.nodes.values() if node.kind == "action"), 1):
            recorded = projected.get("nodes", {}).get(node.id) or {}
            label = node.label or "Connected action " + str(number)
            state = recorded.get("status")
            actions.append({"action": label, "recorded_result": ("Stopped with a problem" if recorded.get("outcome") == 0 else
                             "Finished according to the saved run" if state == "done" else
                             "Not yet confirmed" if state else "No recorded execution")})
        result["run"] = {"status": _STATES.get(run.status, "Needs review"),
                         "used_current_release": bool(published_id and run.release_id == published_id),
                         "release": "Current published release" if published_id and run.release_id == published_id else "An earlier or unpublished saved release",
                         "practice_run": bool(run.dry_run), "actions": actions,
                         "review": ("Waiting for a current action decision" if run.status == "paused_approval" and projected.get("approval_card_status") == "current" else
                                    "Approval needs a fresh review" if run.status == "paused_approval" else "No approval is currently waiting"),
                         "progress": _link(flow_id, run_id, "Open the recorded run result")}
    # Recheck access after gathering records so no stale account or owner can
    # publish an explanation captured before authority changed.
    native.get_flow_endpoint(request, flow_id)
    if run_id:
        native._load_owned_run(request, run_id)
    result["checked_at"] = time.time()
    revision = digest({key: value for key, value in result.items() if key != "checked_at"})
    return revision, result


@router.get("/{flow_id}/explanation")
def workflow_explanation(request: Request, flow_id: str, run_id: str | None = None):
    if not 1 <= len(flow_id) <= 256 or run_id is not None and not 1 <= len(run_id) <= 256:
        raise HTTPException(404, "Open a saved workflow or run to review its explanation.")
    revision, report = explain(request, flow_id, run_id)
    return JSONResponse({"revision": revision, "explanation": report}, headers={"Cache-Control": "private, no-store"})


@asset_router.get("/static/lightwork-workflow-explanation.js", include_in_schema=False)
def explanation_script():
    return FileResponse(Path(__file__).parent / "static" / "lightwork-workflow-explanation.js",
                        media_type="application/javascript; charset=utf-8", headers={"Cache-Control": "no-store"})
