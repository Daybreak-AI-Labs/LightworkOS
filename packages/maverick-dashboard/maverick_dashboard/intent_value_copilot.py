"""Live metric questions with sealed query context, never generated arithmetic."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import HTTPException
from maverick import crypto_at_rest

from . import auth
from .draft_api import context_for
from .intent_value_api import _call, read_report, synced_opportunities

PURPOSE = "lightwork.intent-value-query.v1"
FOLLOWUPS = {"why", "why did it fall", "why did that number fall", "what about last month",
             "last month", "this month", "show me what contributed to that", "what contributed to that",
             "what could we improve", "what about this month"}


def _prior(request, token, permissions):
    if not token:
        return None
    try:
        if not crypto_at_rest.is_sealed_str(token):
            return None
        value = json.loads(crypto_at_rest.unseal_from_str(token))
    except Exception:
        return None  # The ordinary conversation reader validates other tokens.
    if not isinstance(value, dict) or value.get("purpose") != PURPOSE:
        return None
    if (value.get("context") != context_for(request) or value.get("permissions") != sorted(permissions)
            or not 0 <= time.time() - value.get("at", 0) <= 3600):
        raise HTTPException(409, "Your metric context expired or access changed. Ask the scoped question again.")
    return value["query"]


def _dates(message):
    now = datetime.now(timezone.utc)
    month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if "last month" in message:
        end = month - timedelta(days=1)
        return end.replace(day=1).date().isoformat(), end.date().isoformat()
    if "last 30 days" in message:
        return (now - timedelta(days=30)).date().isoformat(), now.date().isoformat()
    return month.date().isoformat(), now.date().isoformat()


def _wants_metric(message, prior):
    return bool(re.search(r"\b(?:roi|net benefit|labor value|time saved|save more|cost us|costs?|spend|delivering|contributed the most|value delivered)\b", message)
                or prior and (message in FOLLOWUPS or isinstance(prior, dict) and prior.get("clarify_kind")))


def _money(value, currency):
    return "unavailable" if value is None or not currency else f"{currency} {value:,.2f}"


def _entities(request, query, kind):
    """Resolve business names only from the caller's authorized current catalog."""
    available = read_report(request, **{**query, "entity_kind": "", "entity_id": ""})["by_entity"]
    choices = {row["id"]: row.get("label", row["id"]) for row in available if row["kind"] == kind}
    if kind == "processes":
        from maverick.flow import store

        from .flows_api import _can_access_flow
        choices.update({flow.id: flow.name for flow in store.list_flows() if _can_access_flow(request, flow)})
    elif kind == "specialists":
        from maverick.domain import available_domains
        choices.update({name: profile.description.split(":")[0] for name, profile in available_domains().items()
                        if auth.domain_suites_allowed(request, name)})
    return choices


def _entity(request, query, message, page, pending=""):
    requested = pending or next((kind for word, kind in (("specialist", "specialists"), ("agent", "agents"),
                      ("process", "processes"), ("workflow", "processes")) if re.search(r"\b" + word + r"\b", message)), "")
    parsed = urlsplit(page)
    page = parsed.path
    if not requested and not any(term in message for term in ("company", "as a whole", "across lightwork")):
        if re.fullmatch(r"/flows/(?:designer/)?[^/]+", page):
            requested = "processes"
        elif re.fullmatch(r"/(?:agents|specialists)/[^/]+", page) or page == "/agents" and parse_qs(parsed.query).get("name"):
            requested = "specialists"
    if not requested or "which agent" in message or "across our company" in message:
        return query, None
    if requested != "processes" and page == "/agents" and parse_qs(parsed.query).get("name"):
        return {**query, "entity_kind": "specialists", "entity_id": parse_qs(parsed.query)["name"][0]}, None
    match = re.fullmatch(r"/(?:agents|specialists)/([^/]+)", page) if requested != "processes" else re.fullmatch(r"/flows/(?:designer/)?([^/]+)", page)
    if match:
        return {**query, "entity_kind": requested, "entity_id": match.group(1)}, None
    available = _entities(request, query, requested)
    candidates = [identifier for identifier, label in available.items() if any(
        re.search(r"(?<!\w)" + re.escape(value.casefold()) + r"(?!\w)", message) for value in (identifier, label) if value)]
    if len(candidates) == 1:
        return {**query, "entity_kind": requested, "entity_id": candidates[0]}, None
    if query.get("entity_kind") == requested and query.get("entity_id") and re.search(r"\b(?:this|that|same)\b", message):
        return query, None
    singular = {"processes": "process", "agents": "agent", "specialists": "specialist"}[requested]
    return {**query, "clarify_kind": requested}, "Which " + singular + " do you mean? Open it or name it so I can use the correct authorized scope."


def _context_token(request, permissions, query):
    context = {"purpose": PURPOSE, "context": context_for(request), "permissions": sorted(permissions), "at": time.time(), "query": query}
    return crypto_at_rest.seal_to_str(json.dumps(context))


def _initial_query(page, start, end):
    query = {"start": start, "end": end, "scope": "own", "intent": "", "entity_kind": "", "entity_id": ""}
    parsed = urlsplit(page)
    if parsed.path == "/work-value":
        selected = parse_qs(parsed.query)
        query.update({key: values[0] for key, values in selected.items() if key in query})
    if query["scope"] not in {"own", "company"} or query["entity_kind"] not in {"", "agents", "specialists", "processes"}:
        raise ValueError("Choose a supported work-value reporting scope.")
    return query


def answer(request, message, page, token, permissions):
    return _call(lambda: _answer(request, message, page, token, permissions))


async def live_answer(request, message, page, token, permissions):
    """Only candidate metric questions enter the blocking reporting service."""
    normalized = " ".join(message.casefold().strip().rstrip("?!. ").split())
    if not _wants_metric(normalized, bool(token)) and not (token and _wants_metric(normalized, _prior(request, token, permissions))):
        return None
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(answer, request, message, page, token, permissions)


def reset_guide_token(request, token, permissions):
    """Leaving metric conversation starts a fresh guide, without replaying data."""
    return "" if _prior(request, token, permissions) is not None else token


def _comparison(request, query, result):
    left, right = (datetime.fromisoformat(query[key]) for key in ("start", "end"))
    previous_end = left - timedelta(days=1)
    previous = {**query, "end": previous_end.date().isoformat(), "start": (previous_end - (right - left)).date().isoformat()}
    earlier = read_report(request, **previous)
    before, current = earlier["totals"], result["totals"]
    previous_costs, current_costs = before["known_execution_costs"], current["known_execution_costs"]
    cost_changes = {unit: round(current_costs.get(unit, 0) - previous_costs.get(unit, 0), 6)
                    for unit in sorted(set(previous_costs) | set(current_costs))}
    old_intents = {row["id"]: row for row in earlier["by_intent"]}
    new_intents = {row["id"]: row for row in result["by_intent"]}
    changes = []
    for identifier in sorted(set(old_intents) | set(new_intents)):
        old, new = old_intents.get(identifier, {}), new_intents.get(identifier, {})
        count = new.get("performed_work", 0) - old.get("performed_work", 0)
        changes.append({"id": identifier, "label": (new or old)["label"], "performed_work_change": count,
                        "previous": old, "current": new})
    changes.sort(key=lambda row: abs(row["performed_work_change"]), reverse=True)
    result["comparison"] = before
    result["comparison_detail"] = {"start": previous["start"], "end": previous["end"],
                                   "cost_changes": cost_changes, "intent_changes": changes}
    prior_cost = ", ".join(_money(value, unit) for unit, value in previous_costs.items()) or "no known cost records"
    reply = (f" The previous equal-length period ({previous['start']} through {previous['end']}, UTC) had "
             f"{before['performed_work']} performed work items, {_money(before['gross_estimated_labor_value'], before['currency'])} "
             f"estimated gross value, known execution costs {prior_cost}, and "
             f"{_money(before['net_estimated_benefit'], before['currency'])} estimated net benefit.")
    if cost_changes:
        reply += " Known execution cost change " + "; ".join(_money(value, unit) for unit, value in cost_changes.items()) + "."
    if changes:
        reply += " Activity changes in performed work: " + "; ".join(
            f"{row['label']} {row['performed_work_change']:+d}" for row in changes[:5]) + ". Multi-intent contributions can overlap."
    if before["cost_incomplete"] or earlier["incomplete"]:
        reply += " The earlier period also has incomplete evidence or cost coverage."
    return reply + " Inspect contributing work and its estimate history for changed assumptions; this comparison does not establish a causal reason."


def _answer(request, message, page, token, permissions):
    normalized = " ".join(message.casefold().strip().rstrip("?!. ").split())
    prior = _prior(request, token, permissions)
    if not _wants_metric(normalized, prior):
        return None
    start, end = _dates(normalized)
    query = dict(prior or _initial_query(page, start, end))
    pending = query.pop("clarify_kind", "")
    if any(term in normalized for term in ("last month", "this month", "last 30 days")):
        query.update(start=start, end=end)
    if any(term in normalized for term in ("company", "lightwork as a whole", "across lightwork")):
        query.update(scope="company", entity_kind="", entity_id="")
    query, clarification = _entity(request, query, normalized, page, pending)
    if clarification:
        return {"reply": clarification, "mode": "live", "source": "Authorized work value",
                "conversation_token": _context_token(request, permissions, query),
                "action_link": {"href": "/work-value", "label": "Choose the reporting scope"}}
    result = read_report(request, **query)
    total, currency = result["totals"], result["totals"]["currency"]
    scope = "your company's authorized Lightwork work" if query["scope"] == "company" else "your authorized work"
    if query["entity_id"]:
        scope += " contributed by " + _entities(request, query, query["entity_kind"]).get(query["entity_id"], query["entity_id"])
    cost = ", ".join(_money(value, unit) for unit, value in total["known_execution_costs"].items()) or "unavailable (no known cost records)"
    reply = (f"For {scope}, {query['start']} through {query['end']} (UTC): "
             f"{total['performed_work']} audit-backed work items; gross estimated labor value "
             f"{_money(total['gross_estimated_labor_value'], currency)}; known execution costs {cost}; "
             f"estimated net benefit {_money(total['net_estimated_benefit'], currency)}.")
    if total["cost_incomplete"] or result["incomplete"]:
        reply += " Evidence or cost coverage is incomplete; missing cost is not free execution."
    reply += " Labor value uses benchmark assumptions, not measured cash savings."
    if normalized.startswith("why"):
        reply += _comparison(request, query, result)
    if "which agent" in normalized or "contributed" in normalized:
        entries = sorted((row for row in result["by_entity"] if row["kind"] == "agents"),
                         key=lambda row: row["gross_estimated_labor_value"] or 0, reverse=True)
        reply += (" Agent contributions by estimated gross labor value: " + "; ".join(
            row.get("label", row["id"]) + " " + _money(row["gross_estimated_labor_value"], row["currency"]) for row in entries[:5]) + ". Contributions overlap and are not additive.") if entries else " No attributed agent contributions are available in this scope."
    if "save more" in normalized or "improve" in normalized:
        suggestions = synced_opportunities(request)
        proposals = suggestions["opportunities"]
        reply += (" " + suggestions["notice"] if not suggestions["recommendations_enabled"] else
                  f" There are {len(proposals)} suggestions for your accessible work. " +
                  (proposals[0]["label"] + ": " + proposals[0]["current_evidence"]["reason"] if proposals else "More identifiable work and completed examples are needed."))
    href = "/work-value?" + urlencode(query)
    return {"reply": reply, "mode": "live", "source": "Work value: shared metric service",
            "checked_at": time.time(), "metrics": result,  # This answer's read recorded new work first.
            "conversation_token": _context_token(request, permissions, query),
            "action_link": {"href": href, "label": "Inspect contributing work and assumptions"}}
