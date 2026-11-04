"""Account-scoped template evidence; never infer a template/pilot association."""
from __future__ import annotations

import hashlib
import hmac
from functools import partial

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from . import outcome_pilot_sources, outcome_pilots
from .auth import assert_template_access, caller_principal, require_permission
from .draft_api import context_for

router = APIRouter(tags=["template-outcomes"])


def project_report(report):
    """Shared projection retaining every planned case and missing evidence.

    Caller must obtain the report through current per-source authorization.
    A case is a planned business result, not a provider attempt.
    """
    from maverick.outcome_accounting import COST_COVERAGE_FAMILIES

    cases = report["cases"]
    paired = [row for row in cases if row.get("status") == "paired"]
    corrected = [row for row in paired if (row.get("measurement") or {}).get("corrections", 0) > 0]
    complete = bool(cases) and len(paired) == len(cases) and all(
        row.get("measurement", {}).get("ai_total_cost") is not None
        and row.get("measurement", {}).get("baseline_cost") is not None
        and set(row.get("measurement", {}).get("cost_coverage") or {}) == set(COST_COVERAGE_FAMILIES)
        and all(value.get("status") in {"included", "zero"} for value in row["measurement"]["cost_coverage"].values())
        for row in paired
    )
    group = report["groups"]["all"]
    complete = bool(complete and group["currency"] and group["reported_cost_difference"] is not None)
    return {"planned_cases": len(cases), "accepted_cases": group["accepted"],
            "failed_cases": sum(row.get("source", {}).get("status") == "failed" for row in cases),
            "cancelled_cases": sum(row.get("source", {}).get("status") == "cancelled" for row in cases),
            "unavailable_cases": sum(row.get("status") == "unavailable" for row in cases),
            "acceptance_rate": group["accepted"] / len(cases) if cases else None,
            "corrected_cases": len(corrected), "correction_observed_cases": len(paired),
            "correction_rate": len(corrected) / len(cases) if cases else None,
            "reported_cost_complete": complete,
            "reported_cost_difference": group["reported_cost_difference"] if complete else None,
            "currency": group["currency"] if complete else None,
            "provider_invoice_verified": False, "attempt_count": None,
            "scope": "Planned business cases; attributed local observations, not a general ROI claim or provider-attempt count."}


def _context(request):
    from maverick import config

    require_permission(request, "operate")
    if config.config_source_errors(include_tenant=True) or config.get_features().get("outcome_measurement") is not True:
        raise HTTPException(403, "Outcome measurement is disabled or unavailable in Settings.")
    return context_for(request)


def _template(request, name):
    from maverick.file_lock import atomic_read_text
    from maverick.templates import load_template

    try:
        template = load_template(name)
        assert_template_access(request, template)
        version = hashlib.sha256(atomic_read_text(template.path, encoding="utf-8").encode()).hexdigest()
        return template, version
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, "Template is unavailable.") from exc


@router.get("/api/v1/templates/{name}/outcomes")
def template_outcomes(request: Request, name: str):
    context = _context(request)
    template, version = _template(request, name)
    # One read per pilot: reading each again was twice the work, and a pilot
    # removed between the two reads failed the whole page.
    page = outcome_pilots.listing(context, limit=200, records=True)
    evidence, choices = [], []
    for record in page["items"]:
        choices.append({"id": record["id"], "title": record["title"], "revision": record["revision"], "workflow": record["workflow"]})
        association = (record.get("template_bindings") or {}).get(name)
        if association is None:
            continue
        report = outcome_pilots.report(record, resolve=partial(outcome_pilot_sources.resolve, request))
        evidence.append({"pilot_id": record["id"], "title": record["title"], "criteria": report["criteria"],
                         "workflow_scope": record["workflow"], "exceptions": association["exceptions"],
                         "template_version": association["version"], "stale": association["version"] != version,
                         "binding_basis": "Explicit author attribution; execution provenance is not independently verified",
                         **project_report(report)})
    return {"name": name, "version": version, "generation": template.generation,
            "context": context, "evidence": evidence, "pilot_choices": choices, "partial": page["partial"],
            "next_cursor": page["page"]["next_cursor"],
            "trial_url": "/workflow-builder?edit=" + name,
            "note": "Choosing a template creates a reviewed draft. A sample does not establish general savings or live compatibility."}


class BindIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    pilot_id: str = Field(min_length=1, max_length=64)
    expected_revision: int = Field(ge=1, strict=True)
    exceptions: str = Field(min_length=1, max_length=2000)
    confirm: bool = False


@router.post("/api/v1/templates/{name}/outcomes/bind")
def bind_template_outcomes(request: Request, name: str, body: BindIn):
    from maverick.privacy_ops import RecordConflict

    from .app import _require_same_origin

    context = _context(request)
    _require_same_origin(request)
    if not body.confirm or not hmac.compare_digest(context, body.context):
        raise HTTPException(409, "Review this association in the current account and workspace.")
    _, version = _template(request, name)
    if not hmac.compare_digest(body.version, version):
        raise HTTPException(409, "Template content changed. Review the association again.")
    try:
        outcome_pilots.get(body.pilot_id, context)
        def mutate(record):
            if record.get("context") != context:
                raise LookupError
            record["template_bindings"] = {**record.get("template_bindings", {}), name: {
                "version": version, "exceptions": body.exceptions, "actor": caller_principal(request) or "local"}}
        updated = outcome_pilots.STORE.update(body.pilot_id, mutate, expected_revision=body.expected_revision,
                                   actor=caller_principal(request) or "local", action="attribute_template_pilot")
        if updated is None:
            raise LookupError
    except LookupError as exc:
        raise HTTPException(404, "Pilot is unavailable in this account and workspace.") from exc
    except RecordConflict as exc:
        raise HTTPException(409, "The pilot changed. Review the association again.") from exc
    return {"associated": True, "execution_started": False}
