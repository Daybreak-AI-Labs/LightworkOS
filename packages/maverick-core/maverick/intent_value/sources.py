"""Read only native observations, execution receipts and metered attempts.

No public endpoint accepts execution claims. Source content is transient and
never copied into the value ledger. A failed read is an unavailable population,
not an empty report. All adapters inherit the current tenant's native storage.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from ..cost_provenance import amount
from ..governed_operations import digest
from .taxonomy import classify

MAX_RECORDS = 10_000
SUCCESS = {"done", "completed", "succeeded", "success"}


def _bounded(rows, label):
    rows = list(rows)
    if len(rows) > MAX_RECORDS:
        raise ValueError(f"{label} exceeds the supported refresh population; no complete total was claimed.")
    return rows


def audit_population():
    from ..audit import default_audit_log, iter_events

    goals, flows, actions, agents = defaultdict(list), defaultdict(list), defaultdict(set), defaultdict(set)
    requests = {}
    for event in iter_events(all_days=True, strict=True, verify=default_audit_log().signing_enabled):
        gid = event.get("goal_id")
        named = event.get("agent")
        if type(gid) is int and event.get("kind") == "goal_start" and named == "orchestrator":
            # Keep only the classification, never copied request content. The
            # run-start snapshot survives later task-map title edits.
            requests[gid] = _classify_request(event.get("title", ""), event.get("description"))
        if (type(gid) is int and event.get("kind") in {"llm_response", "tool_result", "goal_end"}
                and isinstance(named, str) and re.fullmatch(r"[A-Za-z0-9_:./-]{1,120}", named)):
            agents[gid].add(named)
        if (type(gid) is int and event.get("kind") == "goal_end" and event.get("status") in SUCCESS
                and (event.get("agent") == "orchestrator" or event.get("mode") == "source_analysis")):
            goals[gid].append({"id": digest(event), "at": event["ts"], "kind": "goal_end",
                               "status": event["status"], "signed": bool(event.get("sig") or event.get("signature")),
                               "request_intent": requests.get(gid)})
        if event.get("kind") == "tool_result" and event.get("status") == "ok" and type(gid) is int:
            tool = event.get("tool") or event.get("name")
            if isinstance(tool, str) and len(tool) <= 120:
                actions[gid].add(tool)
        if (event.get("kind") == "control_plane_action" and event.get("action") == "intent_value.flow_state"
                and event.get("performed_work_nodes", 0) > 0):
            flows[event.get("run_id")].append({"id": digest(event), "at": event["ts"],
                "run_id": event.get("run_id"),
                "kind": "flow_state", "status": event.get("status"),
                "release_id": event.get("release_id", ""), "revision": event.get("definition_revision", ""),
                "work_node_count": event["performed_work_nodes"],
                "work_node_ids": event.get("performed_work_node_ids")})
    return goals, flows, actions, agents


def _goal_rows(world):
    # list_goals owns decryption and tenant enforcement on SQLite and Postgres.
    goals = _bounded(world.list_goals(limit=MAX_RECORDS + 1), "Task history")
    # Starter-team goals are internal stages of one reviewed occurrence, not
    # independent customer requests or completed business deliverables. Keep
    # their native goals, receipts and costs intact, but exclude them from
    # request/value discovery until a team-occurrence adapter can distinguish
    # partial handoffs, final completion and business acceptance. In particular,
    # three stages must not become three repeated requests in Ekko.
    goals = [goal for goal in goals if not (goal.execution_principal or "").startswith("agent:starter-team.")]
    origins = {int(row[0]): (str(row[1]), str(row[2])) for row in world.query(
        "SELECT goal_id,kind,ref FROM goal_origins")}
    turns = _bounded(world.query(
        "SELECT t.id,t.goal_id,t.conversation_id,t.ts,c.channel FROM turns t "
        "JOIN conversations c ON c.id=t.conversation_id WHERE t.role='user' ORDER BY t.id LIMIT ?",
        (MAX_RECORDS + 1,)), "Conversation history")
    memberships = {int(row[1]): str(row[2]) for row in turns if row[1] is not None}
    return goals, origins, turns, memberships


def _classify_request(title, description):
    detected = classify(title)
    return detected if detected["intents"] else classify(str(title or "") + "\n" + str(description or ""))


def _classify_goal(goal):
    return _classify_request(goal.title, goal.description)


def _executed_intent(goal, receipt, item):
    if receipt.get("request_intent") is not None:
        return receipt["request_intent"]
    note = " Execution-start request snapshot unavailable: initial intent uses current task fields. Correct the activity if this task was renamed or its purpose differs."
    if note not in item["grouping"]:
        item["grouping"] += note
    return _classify_goal(goal)


def _intent_revision(goal):
    return bool(re.match(r"\s*(?:actually|instead|now|correction)\b", goal.title, re.IGNORECASE))


def _group_goals(goals, origins, memberships):
    by_id, anchors, output = {goal.id: goal for goal in goals}, {}, {}
    for goal in sorted(goals, key=lambda value: value.id):
        origin = origins.get(goal.id)
        if origin and origin[0] == "flow_run":
            anchors[goal.id] = "flow:" + origin[1]
            continue
        parent = by_id.get(goal.parent_id)
        # A parent correlation binds process contributions and conversation
        # revisions. Owner mismatch, cycles and missing parents never borrow
        # another person's economic credit.
        key = anchors.get(parent.id) if parent and parent.owner == goal.owner else None
        detected = _classify_goal(goal)
        if detected["new_work"]:
            key = None
        if key is None:
            key = f"goal:{goal.id}"
        anchors[goal.id] = key
        if key.startswith("flow:"):
            continue
        if key not in output:
            output[key] = _observation(key, goal.owner, goal.created_at, detected)
        item = output[key]
        item["sources"].append({"kind": "goal", "id": str(goal.id), "at": goal.created_at})
        item["goal_ids"].append(goal.id)
        if origin and origin[0] in {"schedule", "trigger"}:
            item["processes"].append(origin[0] + ":" + origin[1])
        item["specialists"].extend([goal.domain] if goal.domain else [])
        item["agents"].extend([goal.execution_principal] if goal.execution_principal and not goal.execution_principal.startswith("user:") else [])
        if parent and goal.id not in memberships:
            item["processes"].append(f"goal:{parent.id}")
        if not item["classification"]["intents"] and detected["intents"]:
            item["classification"] = detected
        elif goal.id != int(key.split(":")[1]) and detected["intents"]:
            # Preserve the original task boundary. New requested activities
            # appear as observations for review instead of new full credits.
            for intent in detected["intents"]:
                if intent not in item["observed_intents"]:
                    item["observed_intents"].append(intent)
            if _intent_revision(goal):
                item["classification"] = {**detected, "reason": "The requested activity explicitly changed during related work."}
        item["last_observed_at"] = max(item["last_observed_at"], goal.created_at)
    return output, anchors


def _observation(key, owner, at, classification):
    return {"key": key, "owner": owner, "observed_at": at, "last_observed_at": at,
            "classification": classification, "executed_classification": None,
            "observed_intents": list(classification["intents"]),
            "sources": [], "goal_ids": [], "flow_runs": [], "specialists": [], "agents": [],
            "processes": [], "evidence": [], "costs": [], "actions": [], "performed_at": None,
            "partial_execution": False, "provider_evidence": [],
            "grouping": "Related attempts and revisions share one work item. Separate work requires a separate task or an explicit new-work request.",
            "cost_limitations": ["Provider invoices, external-tool fees, subscriptions and taxes are not completely covered."]}


def _executed_flow_intent(definition, run, receipt, item):
    """A completed route cannot borrow the effort of branches that never ran."""
    candidates = {node.id: node for node in definition.nodes.values()
                  if node.kind in {"agent", "action"}} if definition is not None else {}
    identifiers = receipt.get("work_node_ids")
    if identifiers is None and len(candidates) == 1 and receipt["work_node_count"] == 1:
        identifiers = list(candidates)  # The old count identifies the sole work step.
    valid = (definition is not None and definition.revision == run.definition_revision
             and isinstance(identifiers, list) and all(isinstance(value, str) for value in identifiers)
             and len(set(identifiers)) == len(identifiers) == receipt["work_node_count"]
             and all(value in candidates for value in identifiers))
    if not valid:
        item["grouping"] += " Executed workflow steps cannot be resolved from the receipt and definition; performed work remains unvalued until reviewed."
        return classify("")
    briefs = " and ".join(candidates[value].brief for value in identifiers if candidates[value].kind == "agent")
    if any(candidates[value].kind == "action" for value in identifiers):
        item["grouping"] += " Direct tool actions are execution facts; the workflow name alone does not establish their business effort. Only identifiable executed agent components are valued."
    return classify(briefs)


def _flow_rows(output, anchors, goals, flow_audit):
    from ..flow import store

    runs = _bounded(store.iter_run_metadata(), "Workflow run history")
    roots = {}
    by_id = {run.run_id: run for run in runs}

    def root(run):
        seen = set()
        while run.origin.startswith("retry:") and run.run_id not in seen:
            seen.add(run.run_id)
            prior = by_id.get(run.origin[6:])
            if prior is None or prior.owner != run.owner or prior.flow_id != run.flow_id:
                break
            run = prior
        return run.run_id

    for run in sorted(runs, key=lambda value: (value.created, value.run_id)):
        if run.dry_run:
            continue
        key = "flow:" + root(run)
        roots[run.run_id] = key
        definition = store.load_flow_snapshot(run.definition_digest) if run.definition_digest else store.load_flow(run.flow_id)
        if definition is None:
            detected = classify("")
        else:
            briefs = " and ".join(node.brief for node in definition.nodes.values() if node.kind == "agent")
            detected = classify(briefs or definition.name)
        item = output.setdefault(key, _observation(key, run.owner, run.created, detected))
        item["sources"].append({"kind": "flow", "id": run.run_id, "flow_id": run.flow_id,
                                "revision": run.definition_revision, "at": run.created,
                                "definition_digest": run.definition_digest,
                                "release_digest": run.release_digest, "release_id": run.release_id})
        item["flow_runs"].append(run.run_id)
        item["processes"].append(run.flow_id)
        item["last_observed_at"] = max(item["last_observed_at"], run.created)
        receipts = [row for row in flow_audit.get(run.run_id, []) if row["status"] == "completed"
                    and row["revision"] == run.definition_revision and row["release_id"] == run.release_id]
        if receipts:
            item["evidence"].extend({**row, "full_task": True} for row in receipts)
            item["executed_classification"] = _executed_flow_intent(definition, run, receipts[-1], item)
        else:
            item["evidence"].extend({**row, "full_task": False} for row in flow_audit.get(run.run_id, [])
                if row["revision"] == run.definition_revision and row["release_id"] == run.release_id)
        item["costs"].append({"id": "flow:" + run.run_id, "amount": amount(run.cost_dollars) if run.cost_dollars else None,
                              "currency": "USD", "basis": "estimated", "at": run.updated or run.created,
                              "complete": False, "status": run.status})
    for goal in goals:
        anchor = anchors.get(goal.id, "")
        if anchor.startswith("flow:"):
            key = roots.get(anchor[5:])
            if key in output:
                item = output[key]
                anchors[goal.id] = key
                item["goal_ids"].append(goal.id)
                item["sources"].append({"kind": "goal", "id": str(goal.id), "at": goal.created_at, "flow_run": anchor[5:]})
                item["specialists"].extend([goal.domain] if goal.domain else [])
                item["agents"].extend([goal.execution_principal] if goal.execution_principal and not goal.execution_principal.startswith("user:") else [])


def collect(world) -> list[dict]:
    goals, origins, turns, memberships = _goal_rows(world)
    audit_goals, audit_flows, actions, agents = audit_population()
    output, anchors = _group_goals(goals, origins, memberships)
    _flow_rows(output, anchors, goals, audit_flows)
    for goal in sorted(goals, key=lambda value: value.id):
        item = output.get(anchors.get(goal.id))
        if item is None:
            continue
        # Child goals inside a flow are contribution evidence. Only the flow
        # completion receipt can award its full business-component estimate.
        item["evidence"].extend({**row, "full_task": not item["flow_runs"] and item["key"] == f"goal:{goal.id}"}
                                for row in audit_goals.get(goal.id, []))
        if not item["flow_runs"]:
            if audit_goals.get(goal.id) and (item["key"] == f"goal:{goal.id}" or _intent_revision(goal)):
                item["executed_classification"] = _executed_intent(goal, audit_goals[goal.id][-1], item)
        item["actions"].extend(actions.get(goal.id, set()))
        item["agents"].extend(agents.get(goal.id, set()))
    for item in output.values():
        if item["evidence"]:
            item["partial_execution"] = not any(row["full_task"] for row in item["evidence"])
    from ..episode_reporting import iter_episodes
    for episode in iter_episodes(world):
        item = output.get(anchors.get(episode.goal_id))
        if item is None:
            continue
        item["costs"].append({"id": f"episode:{episode.id}", "goal_id": episode.goal_id, "amount": amount(episode.cost_dollars),
                              "currency": "USD", "basis": "estimated", "at": episode.ended_at or episode.started_at,
                              "complete": episode.ended_at is not None and amount(episode.cost_dollars) is not None,
                              "status": episode.outcome or "in progress"})
    # Retain observed conversation requests that have no Lightwork execution.
    from ..world_model import _dec_field
    for row in turns:
        if row[1] is not None:
            continue
        key = f"conversation:{row[2]}"
        if key not in output:
            raw = world.query("SELECT content FROM turns WHERE id=?", (row[0],))
            output[key] = _observation(key, "unattributed-channel", row[3], classify(_dec_field(raw[0][0])))
        output[key]["sources"].append({"kind": "turn", "id": str(row[0]), "at": row[3]})
    for item in output.values():
        _provider_costs(item)
        _flow_cost_residuals(item)
        for field in ("specialists", "agents", "processes", "actions"):
            item[field] = sorted(set(item[field]))
        item["evidence"] = list({row["id"]: row for row in item["evidence"]}.values())
        if item["evidence"]:
            full = [row for row in item["evidence"] if row["full_task"]]
            item["performed_at"] = min(row["at"] for row in full or item["evidence"])
        item["source_digest"] = digest(item)
    return sorted(output.values(), key=lambda item: (item["observed_at"], item["key"]))


def _flow_cost_residuals(item):
    """Native flow spend includes its agents; preserve any additional spend."""
    retained = []
    for cost in item["costs"]:
        if not cost["id"].startswith("flow:"):
            retained.append(cost)
            continue
        gids = {int(source["id"]) for source in item["sources"] if source.get("flow_run") == cost["id"][5:]}
        children = [row for row in item["costs"] if row.get("goal_id") in gids]
        if not children:
            retained.append(cost)
            continue
        known = sum(row["amount"] or 0 for row in children if row["currency"] == "USD")
        residual = max(0, (cost["amount"] or 0) - known)
        if residual and all(row["currency"] == "USD" for row in children):
            retained.append({**cost, "id": cost["id"] + ":residual", "amount": residual,
                             "status": "Native workflow spend above linked agent costs",
                             "time_basis": "Allocated to the native workflow update time"})
        if any(row["currency"] != "USD" for row in children):
            # Conversion cannot establish overlap. Keep the native total as
            # explanation metadata instead of summing incompatible estimates.
            item["cost_limitations"].append("Native USD workflow spend cannot be reconciled with linked costs in another currency.")
    item["costs"] = retained


def _provider_costs(item):
    """Receipts replace, never add to, their goal's episode estimate.

    Receipt timestamps have month precision. Allocation within that month is
    explicitly estimated; the receipt's native period remains inspectable.
    Mixed instrumentation cannot prove all calls were admitted, so retain an
    unallocated runtime residual when it exceeds the receipt subtotal.
    """
    from ..cost_provenance import for_goal

    for gid in item["goal_ids"]:
        catalogue = for_goal(gid)
        item["provider_evidence"].append({"goal_id": gid, **catalogue})
        receipts = catalogue["receipts"]
        if not receipts:
            if catalogue["state"] == "unavailable":
                item["cost_limitations"].append("Linked provider cost evidence is unavailable.")
            continue
        runtime = [cost for cost in item["costs"] if cost.get("goal_id") == gid]
        by_period = defaultdict(list)
        for cost in runtime:
            by_period[datetime.fromtimestamp(cost["at"], timezone.utc).strftime("%Y-%m")].append(cost)
        for receipt in receipts:
            at = datetime.strptime(receipt["period"], "%Y-%m").replace(tzinfo=timezone.utc).timestamp()
            related = by_period.get(receipt["period"], [])
            if related:
                at = max(cost["at"] for cost in related)
            item["costs"].append({"id": "provider:" + receipt["reference"], "goal_id": gid,
                "amount": receipt["actual"] if receipt["state"] == "settled" else None,
                "currency": receipt["currency"], "basis": "measured" if receipt["basis"] in {"recorded", "reconciled"} else "estimated",
                "at": at, "period": receipt["period"], "time_basis": "Allocated within native provider month; exact incurred date unavailable",
                "complete": False, "status": receipt["state"], "invoice_verified": False})
        periods = {receipt["period"] for receipt in receipts}
        for period in periods:
            related = by_period.get(period, [])
            usd = [receipt for receipt in receipts if receipt["period"] == period and receipt["currency"] == "USD"]
            # With another currency, retain the runtime reference only in the
            # provenance drilldown; totals cannot make a currency conversion.
            known = sum(receipt["actual"] or 0 for receipt in usd if receipt["state"] == "settled")
            residual = max(0, sum(cost["amount"] or 0 for cost in related) - known) if usd else 0
            item["costs"] = [cost for cost in item["costs"] if cost not in related]
            if residual:
                item["costs"].append({"id": f"runtime-residual:{gid}:{period}", "goal_id": gid, "amount": residual,
                    "currency": "USD", "basis": "estimated", "at": max(cost["at"] for cost in related),
                    "complete": False, "status": "Unallocated runtime amount above linked provider receipts"})
        item["cost_limitations"].append("Provider receipts replace overlapping runtime estimates. Receipt day allocation and unmatched runtime residuals are estimated; invoice and call coverage remain incomplete.")
