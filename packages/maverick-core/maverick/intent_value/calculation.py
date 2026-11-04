"""One economic contract for dashboards, explanations and Copilot.

Credit is per business work item, once, on its first eligible execution.
Costs are distinct underlying events in their own period, including failures.
Contribution views overlap intentionally and must not be added together.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from .settings import benchmark, settings
from .taxonomy import definition

METHOD = "intent-value-v1"
NOTICE = (
    "Benchmark-based labor estimates, not verified paid hours or cash savings. "
    "Net compares estimated attributable labor value with known execution costs. "
    "Opportunity and automation forecasts are separate and are never added to executed value."
)


def assumptions(intents, *, size="standard", specialists=(), units=None):
    from ..config import get_value

    cfg = settings()
    departments = get_value()["departments"]
    rates = {departments[name]["hourly_rate"] for name in specialists if name in departments}
    if not cfg["labor_locked"] and not cfg["revision"] and len(rates) == 1:
        cfg.update(hourly_rate=rates.pop(), labor_provenance="Company specialist/department labor-rate configuration")
    return {"method": METHOD, "benchmarks": [benchmark(identifier) for identifier in intents],
            "hourly_rate": cfg["hourly_rate"], "currency": cfg["currency"],
            "labor_provenance": cfg["labor_provenance"], "size": size, "units": dict(units or {}),
            "manual_work": "Only the benchmark component multiplied by Lightwork's share is credited; retained review minutes are subtracted. Other manual work is outside scope."}


def estimate(source, inputs):
    # Draft/review/extraction of the same object may overlap. Credit the
    # largest supported component for that object, not four full baselines.
    components = {}
    for row in inputs["benchmarks"]:
        if row is None:
            continue
        item = definition(row["id"])
        key = item["object"]
        if key not in components or row["minutes"] > components[key]["minutes"]:
            components[key] = row
    state = "estimated" if components else "unknown_intent"
    if inputs.get("size") == "large":
        state = "needs_size_review"
    if source.get("partial_execution"):
        state = "partial_execution"
    result = {"method": METHOD, "state": state, "assumptions": inputs,
              "component_policy": "Largest component per business object; overlapping activities are not additive.",
              "avoided_minutes": None, "potential_gross": None, "range": None,
              "gross": None if source["performed_at"] is not None else 0.0}
    if state != "estimated":
        return result
    def effort(field):
        return sum(max(0, row[field] * row["attributable_share"] - row["review_minutes"]) * inputs.get("units", {}).get(key, 1)
                   for key, row in components.items())
    minutes, low, high = effort("minutes"), effort("low_minutes"), effort("high_minutes")
    value = minutes * inputs["hourly_rate"] / 60
    result.update(avoided_minutes=round(minutes, 2), potential_gross=round(value, 2),
                  range=[round(low * inputs["hourly_rate"] / 60, 2), round(high * inputs["hourly_rate"] / 60, 2)],
                  gross=round(value, 2) if source["performed_at"] is not None else 0.0)
    return result


def contribution(row, *, start, end):
    source, value = row["source"], row["estimates"][-1]
    performed = source["performed_at"] is not None and start <= source["performed_at"] < end
    costs = [cost for cost in source["costs"] if start <= cost["at"] < end]
    amounts, measured, estimated = defaultdict(float), defaultdict(float), defaultdict(float)
    seen, unknown = set(), 0
    for cost in costs:
        if cost["id"] in seen:
            continue
        seen.add(cost["id"])
        if cost["amount"] is None:
            unknown += 1
            continue
        currency = cost["currency"]
        amounts[currency] += cost["amount"]
        (measured if cost["basis"] == "measured" else estimated)[currency] += cost["amount"]
    currency = value["assumptions"]["currency"]
    gross = value["gross"] if performed else 0.0
    known_cost = round(amounts.get(currency, 0), 6) if any(cost["amount"] is not None and cost["currency"] == currency for cost in costs) else None
    # A completed work item without a cost record cannot claim free execution.
    missing = unknown + int(performed and not costs)
    incomplete = bool(missing or any(not cost["complete"] for cost in costs) or source["cost_limitations"])
    compatible = not (set(amounts) - {currency})
    net = None if gross is None or missing or (performed and known_cost is None) or not compatible else round(gross - (known_cost or 0), 2)
    return {"id": row["id"], "label": row["label"], "intents": row["intents"],
            "currency": currency, "observed": start <= source["observed_at"] < end,
            "performed": performed, "performed_at": source["performed_at"],
            "gross": gross, "costs": dict(amounts), "measured_costs": dict(measured),
            "estimated_costs": dict(estimated), "cost_event_count": len(seen),
            "missing_cost_count": missing, "cost_incomplete": incomplete, "net": net,
            "unvalued": performed and gross is None,
            "opportunity": value["potential_gross"] if source["performed_at"] is None and not row.get("converted_to") else 0,
            "remaining_potential": value["potential_gross"] if source["performed_at"] is None and not row.get("converted_to") else 0,
            "converted_to": row.get("converted_to"),
            "state": value["state"], "confidence": row["classification"]["confidence"],
            "specialists": source["specialists"], "agents": source["agents"], "processes": source["processes"],
            "revision": row["revision"], "estimate_version": value["version"]}


def totals(rows):
    currencies = sorted({row["currency"] for row in rows}) or [settings()["currency"]]
    currency = currencies[0] if len(currencies) == 1 else None
    costs, measured, estimated = defaultdict(float), defaultdict(float), defaultdict(float)
    for row in rows:
        for field, output in (("costs", costs), ("measured_costs", measured), ("estimated_costs", estimated)):
            for unit, value in row[field].items():
                output[unit] += value
    gross = round(sum(row["gross"] or 0 for row in rows), 2) if currency else None
    opportunity = round(sum(row["opportunity"] or 0 for row in rows if row["observed"]), 2) if currency else None
    unvalued = sum(row["unvalued"] for row in rows)
    missing = sum(row["missing_cost_count"] for row in rows)
    incompatible = currency is None or bool(set(costs) - {currency})
    net = None if incompatible or unvalued or missing else round(gross - costs.get(currency, 0), 2)
    return {"observed_work": sum(row["observed"] for row in rows),
            "performed_work": sum(row["performed"] for row in rows), "unvalued_work": unvalued,
            "gross_estimated_labor_value": gross, "known_execution_costs": {key: round(val, 6) for key, val in costs.items()},
            "measured_costs": {key: round(val, 6) for key, val in measured.items()},
            "estimated_costs": {key: round(val, 6) for key, val in estimated.items()},
            "net_estimated_benefit": net, "opportunity_value": opportunity, "currency": currency,
            "missing_cost_count": missing, "cost_incomplete": any(row["cost_incomplete"] for row in rows),
            "mixed_currencies": incompatible, "cost_event_count": sum(row["cost_event_count"] for row in rows)}


def report(records, *, start, end, intent="", entity_kind="", entity_id=""):
    selected = [row for row in records if not row.get("deleted") and not row.get("_audit_pending")
                and (not intent or intent in row["intents"])
                and (not entity_kind or entity_id in row["source"][entity_kind])]
    rows = [contribution(row, start=start, end=end) for row in selected]
    rows = [row for row in rows if row["observed"] or row["performed"] or row["cost_event_count"]]
    by_intent, by_entity = [], []
    for identifier in sorted({identifier for row in rows for identifier in row["intents"]}):
        group = [row for row in rows if identifier in row["intents"]]
        by_intent.append({"id": identifier, "label": definition(identifier)["label"], **totals(group)})
    for kind in ("specialists", "agents", "processes"):
        for identifier in sorted({identifier for row in rows for identifier in row[kind]}):
            by_entity.append({"kind": kind, "id": identifier, **totals([row for row in rows if identifier in row[kind]])})
    daily = defaultdict(list)
    for record in selected:
        dates = {datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d")
                 for at in [record["source"]["observed_at"], record["source"]["performed_at"],
                            *(cost["at"] for cost in record["source"]["costs"])]
                 if at is not None and start <= at < end}
        for day in dates:
            left = datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp()
            daily[day].append(contribution(record, start=max(start, left), end=min(end, left + 86400)))
    return {"available": True, "method": METHOD, "notice": NOTICE, "start": start, "end": end,
            "totals": totals(rows), "rows": rows, "by_intent": by_intent, "by_entity": by_entity,
            "daily": [{"day": day, **totals(group)} for day, group in sorted(daily.items())],
            "attribution": "Each work item contributes once to the customer total. Agent, specialist, process and multi-intent views show overlapping contributions; do not add those views.",
            "reconciliation": "Uses the same native episodes as Spend and Savings. Legacy Savings is an attempt-based scenario; this report replaces repeated attempt credits with business work items and requires audit completion. These are alternative estimates, never additive."}
