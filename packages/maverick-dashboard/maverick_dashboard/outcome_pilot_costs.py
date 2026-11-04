"""Reviewed pilot shares of completed provider billing admissions.

The source amount comes only from the cost service. The attribution to cases
remains an operator decision and does not establish invoice authenticity.
"""
from __future__ import annotations

import copy
import math
import time
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from functools import lru_cache

from maverick import ai_cost_roi
from maverick.privacy_ops import RecordConflict

from . import outcome_pilots as pilots


def _money(value):
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def sources(service=None):
    observations, receipts = (service or ai_cost_roi.default_service)._report_observations()
    receipt_heads, receipt_links = {}, {}
    for receipt in receipts:
        if receipt.get("status") != "complete":
            continue
        receipt_heads[receipt["id"]] = {key: receipt.get(key) for key in (
            "id", "revision", "payload_sha256", "normalized_batch_sha256", "collector_id",
            "batch_id", "status", "manifest_citation",
        )}
        for binding in receipt["observation_bindings"]:
            receipt_links.setdefault(binding["observation_id"], []).append((receipt["id"], binding))
    originals = {r["id"]: r for r in observations if not r.get("correction_of_observation_id")}
    grouped = {identifier: [] for identifier in originals}
    for row in observations:
        identifier = row.get("correction_of_observation_id") or row["id"]
        original = originals.get(identifier)
        corrects = row.get("correction_of_source_record_id")
        if (original is None or bool(corrects) != bool(row.get("correction_of_observation_id"))
                or (corrects and corrects != original["source_record_id"]) or any(row[k] != original[k] for k in
                                  ("provider", "source_account_id", "currency", "period_start", "period_end"))):
            raise ValueError("Provider cost corrections have inconsistent source bindings.")
        grouped[identifier].append(row)
    result = {}
    for identifier, rows in grouped.items():
        original = originals[identifier]
        identifiers = {row["id"] for row in rows}
        # Keep immutable source/correction citations and the exact completed
        # receipts, excluding mutable transport/audit queue bookkeeping.
        evidence = [{key: row.get(key) for key in (
            "id", "revision", "source_record_id", "source_cost", "source_payload_sha256",
            "allocation_sha256", "correction_of_observation_id", "correction_reason", "citation",
        )} for row in sorted(rows, key=lambda row: row["id"])]
        grouped_bindings = {}
        for observation_id in sorted(identifiers):
            for receipt_id, binding in receipt_links[observation_id]:
                grouped_bindings.setdefault(receipt_id, []).append(binding)
        bindings = [{**receipt_heads[receipt_id], "observation_bindings": relevant}
                    for receipt_id, relevant in sorted(grouped_bindings.items())]
        with localcontext() as ctx:
            ctx.prec = 50
            total = sum((Decimal(row["source_cost"]) for row in rows), Decimal(0))
        source = {"id": identifier, "provider": original["provider"],
                  "source_account_id": original["source_account_id"], "source_record_id": original["source_record_id"],
                  "period_start": original["period_start"], "period_end": original["period_end"],
                  "currency": original["currency"], "net_cost": _money(total),
                  "correction_count": len(rows) - 1, "observations": evidence, "receipts": bindings}
        source["version"] = pilots.digest(source)
        result[identifier] = source
    return result


def allocate(pilot_id, body, *, context, actor, resolve, service=None):
    record = pilots.get(pilot_id, context)
    request = pilots.digest({k: v for k, v in body.items() if k != "expected_revision"})
    previous = record.get("provider_cost_operations", {}).get(body["operation_id"])
    if previous is not None:
        if previous != request:
            raise RecordConflict("This reference already belongs to a different cost allocation.")
        return record
    source = sources(service).get(body["observation_id"])
    if source is None or source["version"] != body["billing_version"]:
        raise RecordConflict("The billing source or its corrections changed. Review the current admitted cost.")
    if Decimal(source["net_cost"]) < 0:
        raise ValueError(
            "Provider credits cannot be allocated as positive delivery cost. Record or "
            "review a nonnegative provider cost source instead."
        )
    cases = {case["id"]: case for case in record["cases"]}
    shares = body["shares"]
    if len({share["case_id"] for share in shares}) != len(shares):
        raise ValueError("A case can receive only one share of this provider line.")
    if sum(share["basis_points"] for share in shares) > 10000:
        raise ValueError("The case shares cannot exceed 100% of this provider line.")
    for share in shares:
        case = cases.get(share["case_id"])
        if case is None:
            raise LookupError("The selected pilot case does not exist.")
        current = resolve(case["kind"], case["reference"])
        if current["version"] != share["source_version"] or current["input_version"] != case["input_version"]:
            raise RecordConflict("A case changed. Refresh its reviewed result before allocating cost.")
        if current.get("sample"):
            raise ValueError("Sample cases cannot receive provider billing allocations.")
    captured = {"source": source, "shares": copy.deepcopy(shares), "actor": actor,
                "note": body["note"], "observed_at": time.time(), "plan_version": record["plan_version"]}
    captured["allocation_version"] = pilots.digest(captured)

    def mutate(current):
        pilots._owned(current, context)
        operations = current.get("provider_cost_operations", {})
        if len(operations) >= 1000:
            raise ValueError("This pilot reached its cost allocation history limit.")
        allocations = copy.deepcopy(current.get("provider_cost_allocations", {}))
        if source["id"] not in allocations and len(allocations) >= 100:
            raise ValueError("A pilot supports at most 100 provider billing lines.")
        existing = allocations.get(source["id"])
        history = existing.get("history", []) if existing else []
        if existing:
            history = [*history, {k: v for k, v in existing.items() if k != "history"}]
        allocations[source["id"]] = {**captured, "history": history}
        current["provider_cost_allocations"] = allocations
        current["provider_cost_operations"] = {**operations, body["operation_id"]: request}

    saved = pilots.STORE.update(pilot_id, mutate, expected_revision=body["expected_revision"],
                               action="allocate_admitted_provider_cost", actor=actor)
    if saved is None:
        raise RecordConflict("The pilot changed. Refresh before continuing.")
    return saved


def _coverage(record, rows, totals, per_case, current_sources, resolve):
    manifest = pilots.validate_admission_manifest(record, require_complete=True)
    admissions = {
        row["case_id"]: row["admitted_at"] for row in manifest["entries"]
    }
    case_states, accessible = [], True
    for case in record["cases"]:
        try:
            source = resolve(case["kind"], case["reference"])
            started_at = source.get("first_started_at")
            valid = (
                source["input_version"] == case["input_version"]
                and not source.get("sample")
                and source["finished"] is True
                and source.get("unstarted") is not True
                and not isinstance(started_at, bool)
                and isinstance(started_at, (int, float))
                and math.isfinite(started_at)
                and started_at > admissions[case["id"]]
            )
            case_states.append({"id": case["id"], "version": source["version"], "eligible": valid,
                                "accepted": valid and source.get("accepted") is True})
        except Exception:
            accessible = False
            case_states.append({"id": case["id"], "eligible": False, "accepted": False})
    currency = next(iter(totals)) if len(totals) == 1 else None
    missing = [case["id"] for case in case_states if not case["eligible"] or not per_case.get(case["id"])]
    ready = accessible and not missing and currency is not None and all(row["status"] == "current" for row in rows)
    version = pilots.digest({"plan": record["plan_version"], "cases": case_states,
        "allocations": sorted((key, value["allocation_version"]) for key, value in record.get("provider_cost_allocations", {}).items()),
        "billing_catalogue": sorted((key, value["version"]) for key, value in current_sources.items())})
    review = record.get("provider_cost_coverage")
    if review and pilots.digest({k: v for k, v in review.items() if k != "integrity"}) != review.get("integrity"):
        raise ValueError("Provider cost coverage review failed its integrity check.")
    complete = ready and review is not None and review["coverage_version"] == version and review["currency"] == currency
    accepted = sum(case["accepted"] for case in case_states)
    metric = None
    if complete and accepted > 0:
        with localcontext() as ctx:
            ctx.prec = 50
            value = (totals[currency] / Decimal(accepted)).quantize(Decimal("0.000000001"), rounding=ROUND_HALF_EVEN)
        metric = {"amount": _money(value), "currency": currency, "accepted_outcomes": accepted,
                  "planned_cases": len(case_states), "provider_cost_total": _money(totals[currency]),
                  "basis": "admitted_provider_cost_with_operator_reviewed_complete_allocation", "rounded_decimal_places": 9}
    return {"status": "complete" if complete else "needs_review" if ready else "incomplete",
            "version": version, "can_confirm": ready, "currency": currency, "planned_cases": len(case_states),
            "covered_cases": len(case_states) - len(missing), "missing_or_ineligible_cases": missing,
            "accepted_outcomes": accepted, "review": review if accessible else None,
            "provider_cost_per_accepted_outcome": metric,
            "explanation": "Explicitly review all planned cases, including failed attempts and rejected results. Each needs current allocated provider cost, a finished eligible source and one common currency; missing cost is never zero."}


def confirm_coverage(pilot_id, body, *, context, actor, resolve, service=None):
    record = pilots.get(pilot_id, context)
    request = pilots.digest({k: v for k, v in body.items() if k != "expected_revision"})
    previous = record.get("provider_cost_coverage_operations", {}).get(body["operation_id"])
    if previous is not None:
        if previous != request:
            raise RecordConflict("This reference belongs to a different cost coverage review.")
        return record
    coverage = report(record, resolve=resolve, service=service)["coverage"]
    if not coverage["can_confirm"]:
        raise ValueError("Every planned case needs current allocated cost and a finished eligible source in one common currency.")
    if body["coverage_version"] != coverage["version"] or body["currency"] != coverage["currency"]:
        raise RecordConflict("Costs, case outcomes or billing receipts changed. Refresh before reviewing coverage.")
    review = {"coverage_version": coverage["version"], "currency": body["currency"],
              "note": body["note"], "actor": actor, "observed_at": time.time()}
    review["integrity"] = pilots.digest(review)

    def mutate(current):
        pilots._owned(current, context)
        operations = current.get("provider_cost_coverage_operations", {})
        if len(operations) >= 1000:
            raise ValueError("This pilot reached its cost coverage review history limit.")
        history = current.get("provider_cost_coverage_history", [])
        if current.get("provider_cost_coverage"):
            history = [*history, current["provider_cost_coverage"]]
        current["provider_cost_coverage_history"] = history
        current["provider_cost_coverage"] = review
        current["provider_cost_coverage_operations"] = {**operations, body["operation_id"]: request}

    saved = pilots.STORE.update(pilot_id, mutate, expected_revision=body["expected_revision"],
                               action="review_provider_cost_coverage", actor=actor)
    if saved is None:
        raise RecordConflict("The pilot changed. Refresh before continuing.")
    return saved


def report(record, *, resolve, service=None):
    # Allocation histories can cite the same case many times. Resolve each
    # accessible source once for this projection; every new report still
    # reauthorizes and refreshes it. No cache survives the request.
    resolve = lru_cache(maxsize=100)(resolve)
    current_sources = sources(service)
    cases = {case["id"]: case for case in record["cases"]}
    rows, totals, per_case = [], {}, {}
    for allocation in record.get("provider_cost_allocations", {}).values():
        versions = [allocation, *allocation.get("history", [])]
        if any(pilots.digest({k: v for k, v in item.items() if k not in {"history", "allocation_version"}})
               != item.get("allocation_version") for item in versions):
            raise ValueError("Saved provider allocation evidence failed its version check.")
        source = allocation["source"]
        current = current_sources.get(source["id"])
        current_credit = (
            current is not None and Decimal(current["net_cost"]) < 0
        )
        state = (
            "unsupported_credit" if current_credit else
            "current" if current and current["version"] == source["version"] else
            "billing_changed"
        )
        unavailable = False
        for entry, share in [(item, share) for item in versions for share in item["shares"]]:
            case = cases.get(share["case_id"])
            try:
                live = resolve(case["kind"], case["reference"])
                if entry is allocation and (live["version"] != share["source_version"] or live["input_version"] != case["input_version"]):
                    state = "case_changed" if state == "current" else state
            except Exception:
                unavailable = True
        if unavailable:
            rows.append({"status": "source_unavailable"})
            continue
        row = {**allocation, "status": state, "allocated": [], "currency": source["currency"]}
        with localcontext() as ctx:
            ctx.prec = 50
            amount = Decimal(source["net_cost"])
            for share in allocation["shares"]:
                value = amount * Decimal(share["basis_points"]) / Decimal(10000)
                row["allocated"].append({"case_id": share["case_id"], "amount": _money(value)})
                if state == "current":
                    code = source["currency"]
                    totals[code] = totals.get(code, Decimal(0)) + value
                    bucket = per_case.setdefault(share["case_id"], {})
                    bucket[code] = bucket.get(code, Decimal(0)) + value
            row["unallocated_cost"] = _money(amount * (10000 - sum(s["basis_points"] for s in allocation["shares"])) / 10000)
        rows.append(row)
    unsupported_credits = sum(row["status"] == "unsupported_credit" for row in rows)
    return {"status": "partial" if any(row["status"] != "current" for row in rows) else "current",
            "evidence_class": "admitted_provider_cost_with_operator_allocation",
            "provider_invoice_verified": False, "allocations": rows,
            "unsupported_credit_count": unsupported_credits,
            "current_totals_by_currency": {code: _money(value) for code, value in sorted(totals.items())},
            "current_case_totals": {case: {code: _money(value) for code, value in sorted(bucket.items())}
                                    for case, bucket in per_case.items()},
            "coverage": _coverage(record, rows, totals, per_case, current_sources, resolve),
            "limits": ["Provider amounts come from completed billing admissions; invoice authenticity is not independently verified.",
                       "Case attribution is a reviewed operator allocation. Changed billing corrections or case versions invalidate the allocation.",
                       "Currencies are separate. Unallocated, unavailable, and negative credit sources are not treated as zero or included in delivery-cost totals.",
                       "Reported total workflow costs and human/rework costs remain separate; these amounts are never added to reported totals automatically.",
                       "Duplicate allocation is prevented within this pilot. Reuse across different pilots is not a consolidated enterprise cost ledger."]}
