"""Explainable evaluation, preference receipts and before/after estimates.

The evaluator proposes drafts only. A forecast never modifies work value,
tool permissions, self-learning policy, publication or execution authority.
"""
from __future__ import annotations

import time
from collections import defaultdict
from copy import deepcopy

from ..governed_operations import digest
from ..governed_records import GovernedRecordStore
from ..privacy_ops import RecordConflict
from .settings import policy
from .taxonomy import definition

RECOMMENDATIONS = GovernedRecordStore("intent_value_recommendations", "IVR", "intent_value")


def evaluate(records, *, owner, capabilities, persist=True):
    """Proposals from recorded work. ``persist=False`` is a read: nothing is
    created or advanced, and a proposal not yet recorded carries revision 0 until
    the explicit sync records it."""
    if not policy()["enabled"] or not policy()["recommendations"]:
        return []
    groups = defaultdict(list)
    for row in records:
        if row["owner"] == owner and not row.get("deleted") and not row.get("_audit_pending"):
            for identifier in row["intents"]:
                groups[identifier].append(row)
    out = []
    for identifier, rows in groups.items():
        item = definition(identifier)
        executed = [row for row in rows if row["source"]["performed_at"] is not None]
        existing = [cap for cap in capabilities if identifier in cap["intents"]]
        reusable = next((cap for cap in existing if cap["kind"] == "process"), None)
        candidate = reusable or next(iter(existing), None)
        actions = sorted({tool for row in executed for tool in row["source"]["actions"]})
        repeatable = len(rows) >= 3
        supported = len(executed) >= 2 and all(row["estimates"][-1]["state"] == "estimated" for row in executed)
        estimate = _forecast(rows, executed)
        plausible = estimate["incremental_net_per_run"] is not None and estimate["incremental_net_per_run"] > 0
        ready = repeatable and supported and plausible
        if not ready and candidate is None:
            # An observed opportunity remains actionable through Chat and
            # correction even before a reusable automation is justified.
            reason = "Gather distinct work items, audit-backed results and a plausible incremental benefit after costs before proposing automation."
        elif reusable:
            reason = "An accessible existing workflow already covers this requested activity. Reuse it before creating another."
        elif ready:
            reason = "At least three distinct work items and two audit-backed executions support a reusable, human-reviewed sequence."
        else:
            reason = "An existing specialist can help with this work; repeated automation is not yet supported."
        identifier_rec = "IVR-" + digest([owner, identifier])[:32]
        proposal = {"id": identifier_rec, "owner": owner, "intent": identifier, "label": item["label"],
                    "work_ids": [row["id"] for row in rows], "observed_count": len(rows),
                    "executed_count": len(executed), "actions": actions, "reason": reason,
                    "kind": "reuse" if reusable else "draft" if ready else "assist",
                    "draft_supported": ready and reusable is None, "capability": candidate,
                    "steps": [
                        {"id": "inputs", "label": "Choose source material and task requirements", "manual": True, "required_manual": True},
                        {"id": "prepare", "label": item["label"] + " using supplied material", "manual": False, "required_manual": False},
                        {"id": "review", "label": "Review the result and approve its use", "manual": True, "required_manual": True},
                    ],
                    "evaluation": {"repeatability": repeatable, "audited_examples": len(executed),
                        "plausible_incremental_benefit": plausible,
                        "step_evidence": "Requested business activity and audited successful work; private prompt text is not copied into the proposal.",
                        "supported_execution": "Existing governed agent steps with manual input and review; no direct external action is inferred.",
                        "existing_capability": bool(candidate), "human_control": "Source selection, judgment and final approval stay with the customer.",
                        "limitations": ["A draft still requires provider and connection readiness checks in the builder.",
                                        "An observed tool does not grant permission to use it.",
                                        "Repeated intent alone does not establish repeatable data bindings."]},
                    "forecast": estimate, "baseline": {"work_ids": [row["id"] for row in executed],
                        "estimates": [{"work_id": row["id"], "estimate": row["estimates"][-1]} for row in executed]},
                    "status": "offered", "decision_history": [], "draft_id": None, "manual_steps": ["inputs", "review"]}
        if persist:
            current = RECOMMENDATIONS.get(identifier_rec)
            if current is None:
                try:
                    current = RECOMMENDATIONS.create(proposal, action="intent_value.recommended", actor="system",
                                                     effect_guard=require_recommendations)
                except RecordConflict:
                    current = RECOMMENDATIONS.get(identifier_rec)
            current = _advance(current, proposal, records)
        else:
            current = RECOMMENDATIONS.get(identifier_rec) or {**proposal, "revision": 0}
        out.append({**current, "current_evidence": {"observed_count": len(rows), "executed_count": len(executed),
            "work_ids": proposal["work_ids"], "draft_supported": proposal["draft_supported"],
            "capability": candidate, "reason": reason, "potential": _potential(rows)}})
    require_recommendations()
    return out


def require_recommendations():
    effective = policy()
    if not effective["enabled"] or not effective["recommendations"]:
        raise PermissionError("Reusable-work recommendations are turned off. An administrator can review this setting.")


def _advance(current, proposal, records):
    """Version emerging proposals and feed outcomes into the next review.

    Customer decisions freeze their proposal. New evidence updates a separate
    planning reference, never overwrites the accepted forecast or its baseline.
    """
    fields = ("kind", "reason", "draft_supported", "capability", "forecast", "baseline",
              "work_ids", "observed_count", "executed_count", "actions", "evaluation")
    promote = (current["status"] == "offered" and not current["decision_history"]
               and (current["kind"], current["draft_supported"], current["capability"]) !=
               (proposal["kind"], proposal["draft_supported"], proposal["capability"]))
    feedback = outcome(current, records) if any(current.get(key) for key in ("draft_id", "adopted_capability", "linked_goal_ids")) else None
    changed = feedback is not None and current.get("outcome_feedback") != feedback
    if not promote and not changed:
        return current
    def update(row):
        if promote:
            row.setdefault("proposal_history", []).append({"at": time.time(), **{key: deepcopy(row[key]) for key in fields}})
            row.update({key: proposal[key] for key in fields})
        if changed:
            row["outcome_feedback"] = feedback
            row["next_review_reference"] = {
                "execution_cost_per_run": feedback.get("after_known_cost_per_run"),
                "sample_count": feedback.get("observed_runs", 0),
                "qualification": "Latest linked outcomes inform future cost planning; labor forecast remains unvalidated."}
    try:
        return RECOMMENDATIONS.update(current["id"], update, expected_revision=current["revision"],
                                       action="intent_value.recommendation_evidence", actor="system",
                                       effect_guard=require_recommendations)
    except RecordConflict:
        return RECOMMENDATIONS.get(current["id"])


def _forecast(rows, executed):
    valid = [row["estimates"][-1] for row in executed if row["estimates"][-1]["avoided_minutes"] is not None]
    currencies = {row["assumptions"]["currency"] for row in valid}
    amounts = [sum(cost["amount"] for cost in row["source"]["costs"] if cost["amount"] is not None)
               for row in executed if row["source"]["costs"] and all(cost["amount"] is not None and cost["currency"] in currencies for cost in row["source"]["costs"])]
    incremental = min(10, sum(row["avoided_minutes"] for row in valid) / len(valid) * 0.2) if valid else None
    rate = sum(row["assumptions"]["hourly_rate"] for row in valid) / len(valid) if valid else None
    cost = sum(amounts) / len(amounts) if amounts and len(currencies) == 1 else None
    labor = incremental * rate / 60 if incremental is not None and len(currencies) == 1 else None
    return {"currency": next(iter(currencies)) if len(currencies) == 1 else None,
            "incremental_minutes_per_run": round(incremental, 2) if incremental is not None else None,
            "incremental_labor_per_run": round(incremental * rate / 60, 2) if incremental is not None and len(currencies) == 1 else None,
            "execution_cost_per_run": round(cost, 4) if cost is not None else None,
            "incremental_net_per_run": round(labor - cost, 2) if labor is not None and cost is not None else None,
            "cost_coverage": "Incomplete; marginal automation cost and retained human effort require qualification.",
            "assumptions": "Provisional reusable setup benefit: 20% of the assisted effort estimate, capped at 10 minutes per run. Conservative planning net subtracts the entire observed known-cost mean from this incremental labor estimate. Marginal cost, external fees and retained effort remain unqualified; this is not a realized-savings claim.",
            "sample_count": len(rows), "uncertainty": "High; validate the incremental effort and cost after adoption."}


def _potential(rows):
    observed = [row["estimates"][-1] for row in rows if row["source"]["performed_at"] is None and not row.get("converted_to")]
    currencies = {row["assumptions"]["currency"] for row in observed}
    known = [row for row in observed if row["potential_gross"] is not None]
    return {"currency": next(iter(currencies)) if len(currencies) == 1 else None,
        "gross": round(sum(row["potential_gross"] for row in known), 2) if len(currencies) <= 1 else None,
        "range": [round(sum(row["range"][i] for row in known), 2) for i in (0, 1)] if len(currencies) <= 1 else None,
        "unvalued": len(observed) - len(known), "work_count": len(observed)}


def decide(identifier, *, decision, expected_revision, actor, manual_steps, guard):
    if decision not in {"defer", "decline", "keep", "adjust", "reopen"}:
        raise ValueError("Choose a supported customer decision.")
    if set(manual_steps) - {"inputs", "prepare", "review"} or not {"inputs", "review"} <= set(manual_steps):
        raise ValueError("Source selection and final approval must remain manual.")
    def update(row):
        if decision == "adjust" and row.get("draft_id"):
            raise ValueError("Adjust the created draft in the workflow builder; its manual steps are now part of that definition.")
        row["manual_steps"] = sorted(set(manual_steps))
        row["decision_history"].append({"at": time.time(), "actor": actor, "decision": decision,
                                         "manual_steps": row["manual_steps"]})
        row["status"] = {"defer": "deferred", "decline": "declined", "keep": "declined", "reopen": "offered"}.get(decision, row["status"])
    return RECOMMENDATIONS.update(identifier, update, expected_revision=expected_revision,
                                  action="intent_value.decision", actor=actor, effect_guard=guard)


def outcome(recommendation, records, *, pin=True):
    from ..flow import store
    from . import workflow_evidence

    adopted = recommendation.get("adopted_capability") or {}
    draft_id = adopted.get("id") if adopted.get("kind") == "process" else recommendation.get("draft_id")
    if not draft_id:
        rows = [row for row in records if set(row["source"]["goal_ids"]) & set(recommendation.get("linked_goal_ids", []))]
        if not rows:
            return {"state": "not_adopted", "runs": [], "message": "No linked capability has been adopted and executed."}
        return _outcome_rows(recommendation, rows, published=True)
    binding = adopted.get("workflow_binding") if adopted.get("kind") == "process" else recommendation.get("draft_binding")
    if not binding:
        return {"state": "source_unavailable", "runs": [],
                "message": "This earlier selection has no exact workflow evidence. Review and select the workflow again to link future outcomes; prior work remains in platform totals."}
    definition = store.load_flow_snapshot(binding["definition_digest"])
    if definition.id != draft_id or definition.owner != recommendation["owner"]:
        return {"state": "source_unavailable", "runs": [], "message": "The selected workflow evidence is unavailable."}
    release = _release_evidence(recommendation, binding, pin=pin)
    rows = [row for row in records if release and row["owner"] == recommendation["owner"]
            and not row.get("deleted") and not row.get("_audit_pending") and workflow_evidence.matches(row, release)]
    result = _outcome_rows(recommendation, rows, published=release)
    result["release_binding"] = release
    if not release:
        result["message"] = "The selected workflow definition has not been observed as published. Publish that reviewed definition, or review and select the edited workflow again."
    return result


def _release_evidence(recommendation, binding, *, pin=True):
    """Pin the first observed publication before even a metric read converts work.

    This retains evidence of an explicit native publication, including while
    suggestions are disabled; it does not offer or activate a recommendation.
    Capture flow evidence before the record CAS to preserve lock ordering.
    """
    from . import workflow_evidence

    previous = recommendation.get("workflow_release") or recommendation.get("outcome_feedback", {}).get("release_binding")
    release = workflow_evidence.release_for(binding, previous)
    if not pin or not release or binding.get("release_id") or recommendation.get("workflow_release") == release:
        return release
    try:
        current = RECOMMENDATIONS.update(recommendation["id"], lambda row: row.update(workflow_release=release),
            expected_revision=recommendation["revision"], action="intent_value.workflow_publication_observed", actor="system")
    except RecordConflict:
        current = RECOMMENDATIONS.get(recommendation["id"])
    if not current or current.get("_audit_pending"):
        return None
    # A racing selection must not receive the previous selection's credit.
    adopted = current.get("adopted_capability") or {}
    selected = adopted.get("workflow_binding") if adopted.get("kind") == "process" else current.get("draft_binding")
    if selected != binding:
        return None
    pinned = current.get("workflow_release")
    return pinned if pinned and pinned.get("selection") == binding else None


def _outcome_rows(recommendation, rows, *, published):
    performed = [row for row in rows if row["source"]["performed_at"] is not None and not row["source"].get("partial_execution")]
    baseline = recommendation["forecast"].get("execution_cost_per_run")
    currency = recommendation["forecast"]["currency"]
    observed_currencies = {cost["currency"] for row in rows for cost in row["source"]["costs"]}
    if currency is None and len(observed_currencies) == 1:
        currency = observed_currencies.pop()
    comparison = _outcome_comparison(recommendation, rows, performed, currency)
    mean = comparison["after_known_cost_per_run"]
    return {"state": "executed" if performed else "adopted" if published else "draft",
            "runs": [{"work_id": row["id"], "evidence_count": len(row["source"]["evidence"]),
                      "performed": row in performed,
                      "estimated_gross": row["estimates"][-1]["gross"], "costs": row["source"]["costs"]} for row in rows],
            "observed_runs": len(performed), "prior_known_cost_per_run": baseline,
            "currency": currency,
            **comparison, "known_cost_difference": baseline - mean if baseline is not None and mean is not None else None,
            "incremental_labor_estimate_per_run": recommendation["forecast"]["incremental_labor_per_run"] if performed else None,
            "feedback": "Review cost forecast" if mean is not None and baseline is not None and mean > baseline else "More outcome evidence needed" if len(performed) < 3 else "Cost evidence available for the next proposal review",
            "message": "Publication is explicit adoption. Executions are native audit-backed facts. Labor improvement remains the documented before/after assumption; this is not causal proof and is not added again to platform value."}


def _mean_gross(estimates, currency):
    if not estimates or any(value["gross"] is None or value["assumptions"]["currency"] != currency for value in estimates):
        return None
    return sum(value["gross"] for value in estimates) / len(estimates)


def _outcome_comparison(recommendation, rows, performed, currency):
    before = [entry["estimate"] for entry in recommendation["baseline"]["estimates"]]
    prior = _mean_gross(before, currency)
    after = _mean_gross([row["estimates"][-1] for row in performed], currency)
    # All adopted attempts belong in the comparison, including failed work.
    # Unknown cost is retained as a coverage gap, never a free failed attempt.
    costs = {cost["id"]: cost for row in rows for cost in row["source"]["costs"]}
    known = [cost["amount"] for cost in costs.values() if cost["amount"] is not None and cost["currency"] == currency]
    mean = sum(known) / len(performed) if known and performed else None
    snapshots = [value.get("cost_snapshot", []) for value in before] + [row["source"]["costs"] for row in rows]
    missing = any(not group or any(cost["amount"] is None or cost["currency"] != currency for cost in group) for group in snapshots)
    labor = after - prior if after is not None and prior is not None else None
    prior_cost = recommendation["forecast"].get("execution_cost_per_run")
    net = labor + prior_cost - mean if not missing and all(value is not None for value in (labor, prior_cost, mean)) else None
    return {"prior_estimated_labor_per_run": prior, "after_estimated_labor_per_run": after,
            "after_known_cost_per_run": mean, "estimated_incremental_labor_per_run": labor,
            "estimated_incremental_net_per_run": round(net, 2) if net is not None else None,
            "forecast_incremental_net_per_run": recommendation["forecast"]["incremental_net_per_run"],
            "attempt_count": len(rows), "missing_comparison_inputs": missing,
            "comparison_basis": "Before/after benchmark estimates per audit-backed work item; all linked attempt costs, including failures, are divided by performed work count. Changed task mix and assumptions can affect this estimate. External fees remain incomplete; this is not causal proof or additional platform credit."}


def conversions(records, *, pin=True):
    """Allocate observed potential to linked adoption results once, separately
    from economic execution credit. Original opportunities and estimates stay.
    ``pin=False`` (a read) computes the same allocation without recording it.
    """
    indexed = {row["id"]: row for row in records}
    assigned = set()
    for proposal in RECOMMENDATIONS.list(limit=10_001):
        if proposal.get("_audit_pending"):
            continue
        result = outcome(proposal, records, pin=pin)
        targets = [run["work_id"] for run in result["runs"] if run["performed"] and run["work_id"] not in assigned]
        original = [indexed[identifier] for identifier in proposal["work_ids"] if identifier in indexed
                    and proposal["intent"] in indexed[identifier]["intents"]
                    and indexed[identifier]["source"]["performed_at"] is None and not indexed[identifier].get("converted_to")]
        for observation, target in zip(original, targets, strict=False):
            observation.update(converted_to=target, recommendation_id=proposal["id"])
            assigned.add(target)
    return records
