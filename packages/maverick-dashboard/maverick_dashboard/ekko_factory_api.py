"""Find customer work and build native workflow drafts in recoverable batches."""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from maverick.governed_operations import digest
from maverick.work_discovery import DraftReview
from maverick.work_discovery_factory import build_task_flow, review_for_task
from pydantic import Field

from . import auth
from . import ekko_routes as ekko

router = APIRouter(prefix="/api/v1/ekko/build", tags=["ekko"])
BATCH_SIZE = 20


class ScanIn(ekko.DeviceIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    brief: str = Field("", max_length=4000)


class BuildIn(ScanIn):
    scan_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    acknowledge_draft_storage: bool = Field(False, strict=True)


def authority(request, context=None, *, write=False):
    from maverick.flow import enabled

    policy, current = ekko._planning_access(request, context=context)
    if write:
        ekko._app()._require_same_origin(request)
        if not policy["enable"] or not policy["build_enabled"] or not enabled():
            raise HTTPException(409, "Turn on Ekko automatic draft building and Workflows in All settings before building.")
    return policy, current


def _proposal(key, review, source, proof):
    from dataclasses import asdict

    return {"key": key, "review": asdict(review), "label": review.goal, "source": source, "proof": proof}


def _brief_proposals(brief):
    from maverick.intent_value import taxonomy

    lines = list(dict.fromkeys(line.strip(" -\t") for line in brief.splitlines() if line.strip(" -\t")))
    if len(lines) > 20 or any(not 3 <= len(line) <= 1000 for line in lines):
        raise HTTPException(422, "Use up to 20 tasks, one per line, with 3–1000 characters per task.")
    proposals = []
    for line in lines:
        intents = taxonomy.classify(line)["intents"]
        intent = intents[0] if len(intents) == 1 else ""
        proposals.append(_proposal("request:" + digest(line.casefold()), review_for_task(line, intent),
                                   "Your requested work", {"kind": "request", "digest": digest(line)}))
    return proposals


def _guided_review(candidate):
    from dataclasses import replace

    review = review_for_task(candidate["title"])
    steps = "; ".join(f"{index}. {step['action']} {step['object_type']} in {step['app']}"
                      for index, step in enumerate(candidate["pattern"], start=1))
    return replace(review, inputs=review.inputs + " Recorded task outline: " + steps +
                   ". This outline provides context; it does not grant access to these apps.")


def _observed_proposals(request, device, coverage, missing):
    from maverick.work_discovery_store import WorkDiscoveryStoreError

    try:
        plans = ekko._plans(request, device).list()
        store = ekko._store(request, device)
        policy, _ = authority(request)
        current = ekko._candidate_response(store, policy)["candidates"] if store.path.exists() else []
    except (WorkDiscoveryStoreError, ValueError):
        coverage.append({"label": "Recorded work", "message": "Could not read the current evidence. Refresh Ekko before building from it."})
        return []
    candidates = {row["opportunity_id"]: row for row in current}
    proposals, reviewed = [], set()
    for plan in plans:
        identifier = plan["opportunity_id"]
        reviewed.add(identifier)
        if plan["stage"] == "parked":
            continue
        candidate = candidates.get(identifier)
        if candidate is None or candidate["evidence_revision"] != plan["evidence_revision"]:
            missing.append({"label": plan["review"]["goal"], "message": "Review the current recorded pattern before rebuilding this task.", "href": "/ekko"})
            continue
        proposals.append(_proposal("observed:" + device + ":" + identifier, DraftReview(**plan["review"]),
            "Reviewed recorded work", {"kind": "plan", "id": identifier, "revision": plan["revision"],
                                        "evidence_revision": plan["evidence_revision"]}))
    for identifier, candidate in candidates.items():
        if identifier not in reviewed:
            if candidate["observation_basis"] == "guided":
                review = _guided_review(candidate)
                proposals.append(_proposal("observed:" + device + ":" + identifier, review,
                    "Guided recorded task steps", {"kind": "guided", "id": identifier,
                                                   "evidence_revision": candidate["evidence_revision"]}))
            else:
                missing.append({"label": candidate["title"], "message": "App activity does not identify the business task. Describe it once in the opportunity review.", "href": "/ekko#ekko-opportunities-heading"})
    coverage.append({"label": "Recorded work", "message": f"{len(current)} current patterns; {len(proposals)} reviewed or guided tasks available; parked plans excluded."})
    return proposals


def _work_proposals(request, coverage):
    from maverick.intent_value import opportunities, settings, taxonomy

    from . import intent_value_api as work

    if not settings.policy()["enabled"] or not settings.policy()["recommendations"]:
        coverage.append({"label": "Work in Lightwork", "message": "Work value recommendations are off. Enable them in All settings to discover repeated business tasks."})
        return []
    try:
        rows = work.records(request)
    except (HTTPException, ValueError, PermissionError):
        coverage.append({"label": "Work in Lightwork", "message": "Work history is unavailable under current access. Other authorized sources can still be used."})
        return []
    groups = defaultdict(list)
    for row in rows:
        if not row.get("_audit_pending"):
            for intent in row["intents"]:
                if taxonomy.definition(intent):
                    groups[intent].append(row)
    proposals = []
    for intent, records in sorted(groups.items()):
        if len({row["id"] for row in records}) < 3:
            continue
        item = taxonomy.definition(intent)
        decision_id = "IVR-" + digest([auth.goal_owner_filter(request), intent])[:32]
        decision = opportunities.RECOMMENDATIONS.get(decision_id)
        if decision and (decision.get("_audit_pending") or decision["status"] in {"declined", "deferred"}
                         or "prepare" in decision.get("manual_steps", [])):
            continue
        proofs = sorted([[row["id"], row["revision"]] for row in records])
        proposals.append(_proposal("work:" + intent, review_for_task(item["label"], intent),
            f"{len(proofs)} distinct requests in Lightwork", {"kind": "work", "records": proofs, "decision": decision_id}))
    coverage.append({"label": "Work in Lightwork", "message": f"Reviewed {len(rows)} accessible work records; found {len(proposals)} repeated business tasks. Requests do not prove successful execution."})
    return proposals


def _connections(request, coverage):
    from .connection_dependencies import connection_attention

    state = connection_attention(request)
    coverage.append({"label": "Connections", "message":
        f"{len(state['items'])} connections need attention. Account readiness only; external system contents were not scanned."
        if state["coverage"] == "current" else "Connection readiness is unavailable or disabled. External system contents were not scanned."})
    return state["items"]


def scan(request, body):
    from maverick.flow import enabled, store

    policy, context = authority(request, body.context)
    device = ekko._device_id(body.device_id)
    coverage, missing = [], []
    proposals = _brief_proposals(body.brief)
    proposals += _observed_proposals(request, device, coverage, missing)
    proposals += _work_proposals(request, coverage)
    connections = _connections(request, coverage)
    owner = auth.caller_principal(request) or ""
    # Exact business titles deduplicate repeated sources; customer-entered context wins.
    unique = {}
    for row in proposals:
        unique.setdefault(" ".join(row["label"].casefold().split()), row)
    proposals = list(unique.values())
    if len(proposals) > 250:
        raise HTTPException(422, "Too many tasks for one discovery pass. Review the existing shortlist before adding more work.")
    owned = [flow for flow in store.list_flows() if flow.owner == owner]
    by_name = {" ".join(flow.name.casefold().split()): flow for flow in owned}
    for row in proposals:
        row["flow_id"] = "ekko-built-" + digest([owner, row["key"]])[:32]
        existing = store.load_flow(row["flow_id"]) or by_name.get(" ".join(row["label"].casefold().split()))
        if existing is not None and existing.owner != owner:
            raise HTTPException(409, "A draft reference is unavailable. Refresh before building.")
        if existing is not None:
            row["flow_id"] = existing.id
        row["state"] = "existing" if existing else "ready"
        row["href"] = "/flows/designer/" + quote(row["flow_id"], safe="") if existing else ""
    revision = digest([context, device, body.brief, [(row["key"], row["review"], row["proof"]) for row in proposals]])
    authority(request, body.context)
    return {"context": context, "scan_revision": revision, "proposals": proposals, "missing": missing,
            "coverage": coverage, "connections": connections, "enabled": bool(policy["enable"] and policy["build_enabled"] and enabled()),
            "ready": sum(row["state"] == "ready" for row in proposals), "existing": sum(row["state"] == "existing" for row in proposals)}


def public_scan(value):
    return {**value, "proposals": [{key: row[key] for key in ("label", "source", "state", "href")} for row in value["proposals"]]}


def _source_guard(request, body, proposal):
    authority(request, body.context, write=True)
    proof = proposal["proof"]
    if proof["kind"] in {"plan", "guided"}:
        plans = ekko._plans(request, body.device_id).list()
        plan = next((row for row in plans if row["opportunity_id"] == proof["id"]), None)
        if proof["kind"] == "guided" and plan is not None:
            raise HTTPException(409, "Task context changed. Refresh discovery before building.")
        if proof["kind"] == "plan" and (plan is None or plan["revision"] != proof["revision"] or plan["stage"] == "parked"):
            raise HTTPException(409, "The source plan changed or was removed. Refresh the discovery results.")
        policy, _ = authority(request, body.context)
        candidate = ekko._candidate(ekko._store(request, body.device_id), policy, proof["id"])
        if candidate.to_dict()["evidence_revision"] != proof["evidence_revision"]:
            raise HTTPException(409, "Recorded evidence changed. Review the current opportunity before building.")
    elif proof["kind"] == "work":
        from . import intent_value_api as work

        work.authority(request)
        if not work.settings.policy()["recommendations"]:
            raise HTTPException(409, "Work recommendations were turned off. Refresh discovery.")
        decision = work.opportunities.RECOMMENDATIONS.get(proof["decision"])
        if decision and (decision.get("_audit_pending") or decision["status"] in {"declined", "deferred"}
                         or "prepare" in decision.get("manual_steps", [])):
            raise HTTPException(409, "This work was deferred, declined or kept manual. Review that decision before building.")
        current = {row["id"]: row["revision"] for row in work.records(request, refresh=False)}
        if any(current.get(identifier) != revision for identifier, revision in proof["records"]):
            raise HTTPException(409, "The source work changed or became unavailable. Refresh discovery.")


def build(request, body):
    from maverick.audit import EventKind

    from .api_schemas import FlowSaveIn
    from .flows_api import _save_flow_definition

    authority(request, body.context, write=True)
    if not body.acknowledge_draft_storage:
        raise HTTPException(422, "Confirm that Ekko may save private workflow drafts for the discovered work.")
    current = scan(request, body)
    if current["scan_revision"] != body.scan_revision:
        raise HTTPException(409, "The discovered work changed. Scan again before building.")
    pending = [row for row in current["proposals"] if row["state"] == "ready"]
    results = []
    for proposal in pending[:BATCH_SIZE]:
        try:
            _source_guard(request, body, proposal)
            flow = build_task_flow(DraftReview(**proposal["review"]), identifier=proposal["flow_id"])
            ekko._audit(EventKind.EKKO_EXPORT, required=True, artifact_kind="flow", state="automatic_draft_requested",
                        opportunity_id=digest(proposal["key"]), unsaved=False)
            _save_flow_definition(request, FlowSaveIn(flow=flow.to_dict()),
                effect_guard=lambda proposal=proposal: _source_guard(request, body, proposal))
            results.append({"label": proposal["label"], "state": "built", "href": "/flows/designer/" + quote(flow.id, safe="")})
        except HTTPException as exc:
            if exc.status_code in {401, 403}:
                raise
            results.append({"label": proposal["label"], "state": "blocked", "message":
                exc.detail if isinstance(exc.detail, str) else "Workspace or access changed. Refresh the page."})
        except (ValueError, OSError):
            results.append({"label": proposal["label"], "state": "blocked", "message": "This draft could not be confirmed. Scan again to inspect what was saved."})
    authority(request, body.context, write=True)
    return {"results": results, "built": sum(row["state"] == "built" for row in results),
            "blocked": sum(row["state"] == "blocked" for row in results), "existing": current["existing"],
            "remaining": max(0, len(pending) - BATCH_SIZE), "started_work": False, "published": False}


@router.get("/options")
def options_endpoint(request: Request):
    from maverick.flow import enabled

    policy, context = authority(request)
    return {"context": context, "enabled": bool(policy["enable"] and policy["build_enabled"] and enabled())}


@router.post("/scan")
def scan_endpoint(request: Request, body: ScanIn):
    ekko._app()._require_same_origin(request)
    return public_scan(scan(request, body))


@router.post("/drafts")
def build_endpoint(request: Request, body: BuildIn):
    return build(request, body)
