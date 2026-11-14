"""Security/GRC and defensive-hunter REST surfaces.

Mounted below ``/api/v1`` by :mod:`maverick_dashboard.api`. Keeping this
department router separate prevents the already-large shared API module from
becoming the ownership boundary for every security record type.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from . import api_schemas as schemas
from .auth import require_global_permission, require_permission

log = logging.getLogger(__name__)

router = APIRouter(prefix="/security", tags=["security"])

from .assurance_pickers_api import router as assurance_pickers_router  # noqa: E402
from .governance_api import router as governance_router  # noqa: E402
from .identity_governance_outcomes_api import (  # noqa: E402
    router as identity_governance_outcomes_router,
)
from .model_risk_api import router as model_risk_router  # noqa: E402

router.include_router(identity_governance_outcomes_router)
router.include_router(model_risk_router)
router.include_router(assurance_pickers_router)
router.include_router(governance_router)


def _actor(request: Request) -> str:
    # Import lazily: api.py mounts this router after defining the stricter
    # authenticated/local actor resolver, avoiding an import cycle.
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


def _document_principal(request: Request) -> str | None:
    """Reuse the dashboard's authenticated connector-credential boundary."""

    from .request_identity import document_source_principal as _document_source_principal

    return _document_source_principal(request)


def _ops():
    from maverick import security_ops

    if not security_ops.enabled():
        raise HTTPException(
            status_code=403,
            detail="security ops are disabled ([security_ops] enable)",
        )
    return security_ops


async def _ops_call(ops, fn: Callable, *args, **kwargs):
    """Run one synchronous store mutation with stable HTTP conflict semantics."""
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except ops.RecordConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.SecurityTransitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ops.SecurityAuditOutboxError, ops.SecurityStateError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


async def _ops_record_call(ops, fn: Callable, *args, **kwargs) -> dict:
    """Call a record operation and map an unknown record to HTTP 404."""
    result = await _ops_call(ops, fn, *args, **kwargs)
    if result is None:
        raise HTTPException(status_code=404, detail="no such security record")
    return result


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _viewer_readiness(value: object) -> dict[str, Any]:
    """Return readiness aggregates without leaking nested control-owner text."""
    if not isinstance(value, dict):
        return {}
    safe = {
        key: _jsonable(value[key])
        for key in (
            "framework",
            "controls_total",
            "controls_applicable",
            "controls_implemented",
            "controls_partial",
            "coverage_percent",
            "approved_evidence",
            "review_gated_evidence",
            "note",
        )
        if key in value
    }
    gaps = value.get("top_control_gaps")
    if isinstance(gaps, list):
        # Viewer-tier summaries may expose aggregate status and stable control
        # references, but not the owner or descriptive title nested inside each
        # otherwise-innocent readiness object.
        safe["top_control_gaps"] = [
            {
                key: row[key]
                for key in ("id", "canonical_id", "status")
                if key in row
            }
            for row in gaps[:10]
            if isinstance(row, dict)
        ]
    return safe


# Security/GRC aggregate + configuration ------------------------------------

@router.get("/summary")
async def security_summary(request: Request) -> dict:
    """Viewer-safe aggregate: counts/readiness only, no evidence or case text."""
    require_permission(request, "view")
    ops = _ops()
    report = await _ops_call(ops, ops.program_report)
    keys = (
        "assessments", "controls", "evidence", "risks", "poam",
        "vendors", "policies", "incidents", "audits",
    )
    totals = {}
    for key in keys:
        value = report.get(key, {})
        totals[key] = value.get("total", 0) if isinstance(value, dict) else value
    return {
        "enabled": True,
        "generated_at": report.get("generated_at"),
        "totals": totals,
        "readiness": _viewer_readiness(report.get("readiness")),
    }


@router.get("/report")
async def security_report(request: Request, framework: str = "") -> dict:
    require_permission(request, "operate")
    ops = _ops()
    if framework.strip():
        return await _ops_call(
            ops, ops.readiness_report, framework=framework.strip()[:120]
        )
    return await _ops_call(ops, ops.program_report)


@router.get("/regulatory-clocks")
async def regulatory_clock_packs(request: Request) -> dict:
    require_permission(request, "view")
    ops = _ops()
    return {"clocks": await _ops_call(ops, ops.list_regulatory_clock_packs)}


@router.get("/config")
def security_config(request: Request) -> dict:
    """Admin-only effective booleans and enabled connector names; never credentials."""
    require_global_permission(request, "admin")
    from maverick.config import config_source_errors, load_global_config

    from maverick_dashboard import settings_store

    config = load_global_config() or {}
    config_degraded = bool(config_source_errors(include_tenant=False))
    security = config.get("security_ops") or {}
    platform = config.get("threat_hunt") or {}
    environment = config.get("env_hunt") or {}
    connectors = environment.get("connectors") or {}
    if isinstance(connectors, dict):
        connector_names = sorted(
            str(name)
            for name, value in connectors.items()
            if value is True
            or (isinstance(value, dict) and value.get("enable") is True)
        )
    elif isinstance(connectors, list):
        connector_names = sorted(str(name) for name in connectors)
    else:
        connector_names = []
    if config_degraded:
        connector_names = []
    result = {
        "security_ops": not config_degraded and security.get("enable", True) is True,
        "threat_hunt": not config_degraded and platform.get("enable", False) is True,
        "env_hunt": not config_degraded and environment.get("enable", False) is True,
        "response_execution": (
            not config_degraded
            and environment.get("response_execution", False) is True
        ),
        "connectors": connector_names,
        "revision": settings_store.security_suite_revision(),
    }
    if config_degraded:
        result["config_degraded"] = True
    return result


@router.put("/config")
async def update_security_config(
    request: Request, body: schemas.SecuritySuiteConfigIn,
) -> dict:
    require_global_permission(request, "admin")
    from maverick_dashboard import settings_store

    try:
        await run_in_threadpool(
            settings_store.set_security_suite,
            security_ops=body.security_ops,
            threat_hunt=body.threat_hunt,
            env_hunt=body.env_hunt,
            response_execution=body.response_execution,
            actor=_actor(request),
            expected_revision=body.expected_revision,
        )
    except settings_store.SecuritySuiteRevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="security-suite configuration was not committed",
        ) from exc
    from maverick.config import config_source_errors, load_global_config

    effective = load_global_config() or {}
    source_errors = config_source_errors(include_tenant=False)
    should_run_scheduler = not source_errors and any(
        isinstance(effective.get(name), dict)
        and effective[name].get("enable") is True
        for name in ("threat_hunt", "env_hunt")
    )
    scheduler_degraded = ""
    try:
        if should_run_scheduler:
            await run_in_threadpool(start_hunter_scheduler)
        else:
            await run_in_threadpool(stop_hunter_scheduler)
    except Exception as exc:  # config is already durable; report reconciliation need
        scheduler_degraded = (
            "start_failed" if should_run_scheduler else "stop_failed"
        )
        log.error(
            "security hunter scheduler reconciliation failed: %s",
            type(exc).__name__,
        )
    result = await run_in_threadpool(security_config, request)
    if scheduler_degraded:
        result["scheduler_degraded"] = scheduler_degraded
    return result


@router.put("/regulatory-clocks")
async def upsert_regulatory_clock(
    request: Request, body: schemas.SecurityClockIn,
) -> dict:
    require_global_permission(request, "admin")
    ops = _ops()
    payload = body.model_dump(exclude_none=True)
    clock_id = payload.pop("clock_id", "")
    expected = payload.pop("expected_revision", None)
    return await _ops_record_call(
        ops,
        ops.upsert_regulatory_clock,
        payload,
        clock_id=clock_id,
        updated_by=_actor(request),
        expected_revision=expected,
    )


# Controls, crosswalks, and evidence ----------------------------------------

@router.get("/controls")
async def list_controls(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"controls": await _ops_call(ops, ops.list_controls)}


@router.post("/controls", status_code=201)
async def create_control(request: Request, body: schemas.SecurityControlIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.upsert_control,
        body.model_dump(),
        updated_by=_actor(request),
    )


@router.post("/controls/initialize", status_code=201)
async def initialize_controls(request: Request, owner: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    owner = owner.strip()
    if not owner:
        raise HTTPException(status_code=422, detail="control owner must not be blank")
    rows = await _ops_call(
        ops,
        ops.initialize_control_register,
        owner=owner[:200],
        created_by=_actor(request),
    )
    return {"controls": rows, "created": len(rows)}


@router.get("/controls/{control_id}")
async def get_control(request: Request, control_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_control, control_id[:160])
    if record is None:
        raise HTTPException(status_code=404, detail="no such control")
    return record


@router.patch("/controls/{control_id}")
async def update_control(
    request: Request,
    control_id: str,
    body: schemas.SecurityControlUpdateIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    payload = body.model_dump(exclude_none=True)
    expected = payload.pop("expected_revision")
    return await _ops_record_call(
        ops,
        ops.upsert_control,
        payload,
        control_id=control_id[:160],
        expected_revision=expected,
        updated_by=_actor(request),
    )


@router.get("/statement-of-applicability")
async def statement_of_applicability(request: Request, framework: str = "") -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {
        "controls": await _ops_call(
            ops, ops.statement_of_applicability, framework.strip()[:120]
        )
    }


@router.get("/crosswalk")
async def control_crosswalk(
    request: Request, control_id: str = "", framework: str = "",
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {
        "crosswalk": await _ops_call(
            ops,
            ops.control_crosswalk,
            control_id=control_id[:160],
            framework=framework[:120],
        )
    }


@router.get("/evidence")
async def list_evidence(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"evidence": await _ops_call(ops, ops.list_evidence)}


@router.post("/evidence", status_code=201)
async def map_evidence(request: Request, body: schemas.SecurityEvidenceIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.map_evidence,
        body.title,
        body.text,
        source=body.source,
        control_ids=body.control_ids,
        submitted_by=_actor(request),
    )


@router.get("/evidence-documents")
async def search_evidence_documents(request: Request, subject: str = "") -> dict:
    """Search configured sources for policies, logs, and assurance evidence."""

    require_permission(request, "operate")
    _ops()
    query = subject.strip()
    if not query:
        raise HTTPException(status_code=422, detail="evidence subject is required")
    from maverick import doc_discovery

    principal = _document_principal(request)
    allow_ambient = principal is None
    configured = await run_in_threadpool(
        doc_discovery.configured_sources,
        principal=principal,
        allow_ambient_credentials=allow_ambient,
    )
    if not doc_discovery.enabled() or not configured:
        return {"enabled": False, "hits": []}
    hits = await run_in_threadpool(
        doc_discovery.discover,
        query[:300],
        keywords=(
            "security policy",
            "configuration",
            "audit evidence",
            "attestation",
            "access review",
            "security log",
        ),
        sources=configured,
        principal=principal,
        allow_ambient_credentials=allow_ambient,
    )
    return {"enabled": True, "hits": [hit.to_dict() for hit in hits]}


@router.post("/evidence/from-document", status_code=201)
async def map_evidence_from_document(
    request: Request,
    body: schemas.SecurityEvidenceFromDocumentIn,
) -> dict:
    """Fetch bounded source bytes, extract text, and create untrusted evidence."""

    require_permission(request, "operate")
    ops = _ops()
    principal = _document_principal(request)
    try:
        return await run_in_threadpool(
            ops.map_evidence_from_document,
            body.title,
            body.source,
            body.doc_id,
            ref=body.ref,
            control_ids=body.control_ids,
            submitted_by=_actor(request),
            principal=principal,
            allow_ambient_credentials=principal is None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (ops.SecurityAuditOutboxError, ops.SecurityStateError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - source failure details stay private
        raise HTTPException(
            status_code=502,
            detail="document source request failed",
        ) from exc


@router.get("/evidence/{evidence_id}")
async def get_evidence(request: Request, evidence_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_evidence, evidence_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such evidence")
    return record


@router.post("/evidence/{evidence_id}/decision")
async def decide_evidence(
    request: Request,
    evidence_id: str,
    body: schemas.SecurityEvidenceDecisionIn,
) -> dict:
    require_permission(request, "operate", api_scope="approvals:decide")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.decide_evidence,
        evidence_id[:80],
        body.decision,
        body.rationale,
        _actor(request),
        body.expected_revision,
    )


@router.post("/controls/{control_id}/evidence")
async def apply_control_evidence(
    request: Request,
    control_id: str,
    body: schemas.SecurityEvidenceApplyIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.apply_evidence_to_control,
        control_id[:160],
        body.evidence_id,
        body.implementation_status,
        _actor(request),
        body.expected_revision,
    )


# Risk, exceptions, and POA&M -----------------------------------------------

@router.get("/risks")
async def list_risks(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"risks": await _ops_call(ops, ops.list_risks)}


@router.post("/risks", status_code=201)
async def create_risk(request: Request, body: schemas.SecurityRiskIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.register_risk,
        body.title,
        body.likelihood,
        body.impact,
        body.owner,
        description=body.description,
        control_ids=body.control_ids,
        likelihood_rationale=body.likelihood_rationale,
        impact_rationale=body.impact_rationale,
        evidence_ids=body.evidence_ids,
        created_by=_actor(request),
    )


@router.get("/risks/{risk_id}")
async def get_risk(request: Request, risk_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_risk, risk_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such risk")
    return record


@router.post("/risks/{risk_id}/treatment")
async def set_risk_treatment(
    request: Request, risk_id: str, body: schemas.SecurityRiskTreatmentIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.set_risk_treatment,
        risk_id[:80],
        body.treatment,
        body.plan,
        body.residual_likelihood,
        body.residual_impact,
        body.owner,
        _actor(request),
        body.expected_revision,
        residual_likelihood_rationale=body.residual_likelihood_rationale,
        residual_impact_rationale=body.residual_impact_rationale,
        evidence_ids=body.evidence_ids,
    )


@router.post("/risks/{risk_id}/exception")
async def grant_risk_exception(
    request: Request, risk_id: str, body: schemas.SecurityRiskExceptionIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.grant_risk_exception,
        risk_id[:80],
        body.owner,
        body.rationale,
        body.expires_at,
        _actor(request),
        body.expected_revision,
    )


@router.post("/risks/{risk_id}/close")
async def close_risk(
    request: Request, risk_id: str, body: schemas.SecurityCloseIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.close_risk,
        risk_id[:80],
        body.rationale,
        _actor(request),
        body.expected_revision,
    )


@router.get("/poams")
async def list_poams(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"poams": await _ops_call(ops, ops.list_poams)}


@router.post("/poams", status_code=201)
async def create_poam(request: Request, body: schemas.SecurityPoamIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.create_poam,
        body.finding,
        body.owner,
        body.due_at,
        control_ids=body.control_ids,
        milestones=body.milestones,
        created_by=_actor(request),
    )


@router.get("/poams/{poam_id}")
async def get_poam(request: Request, poam_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_poam, poam_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such POA&M")
    return record


@router.patch("/poams/{poam_id}")
async def update_poam(
    request: Request, poam_id: str, body: schemas.SecurityPoamUpdateIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.update_poam,
        poam_id[:80],
        body.status,
        owner=body.owner,
        due_at=body.due_at,
        milestones=body.milestones,
        note=body.note,
        updated_by=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/poams/{poam_id}/review")
async def trigger_poam_review(
    request: Request, poam_id: str, body: schemas.SecurityReviewTriggerIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.trigger_poam_review,
        poam_id[:80],
        body.reason,
        _actor(request),
        body.expected_revision,
    )


# Vendor, policy, and incident lifecycle ------------------------------------

@router.get("/vendors")
async def list_vendors(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"vendors": await _ops_call(ops, ops.list_vendor_assessments)}


@router.post("/vendors", status_code=201)
async def assess_vendor(request: Request, body: schemas.SecurityVendorIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.assess_vendor,
        body.name,
        body.posture,
        criticality=body.criticality,
        owner=body.owner,
        services=body.services,
        assessment_id=body.assessment_id,
        carry_forward_from=body.carry_forward_from,
        assessed_by=_actor(request),
    )


@router.get("/vendors/{vendor_id}")
async def get_vendor(request: Request, vendor_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_vendor_assessment, vendor_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such vendor assessment")
    return record


@router.post("/vendors/{vendor_id}/decision")
async def decide_vendor(
    request: Request, vendor_id: str, body: schemas.SecurityDecisionIn,
) -> dict:
    require_permission(request, "operate", api_scope="approvals:decide")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.decide_vendor_assessment,
        vendor_id[:80],
        body.decision,
        body.rationale,
        _actor(request),
        body.expected_revision,
    )


@router.get("/policies")
async def list_policies(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"policies": await _ops_call(ops, ops.list_policies)}


@router.post("/policies", status_code=201)
async def create_policy(request: Request, body: schemas.SecurityPolicyIn) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.create_policy,
        body.title,
        body.owner,
        content_ref=body.content_ref,
        review_cadence_days=body.review_cadence_days,
        created_by=_actor(request),
    )


@router.get("/policies/{policy_id}")
async def get_policy(request: Request, policy_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_policy, policy_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such policy")
    return record


@router.post("/policies/{policy_id}/transition")
async def transition_policy(
    request: Request, policy_id: str, body: schemas.SecurityPolicyTransitionIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.transition_policy,
        policy_id[:80],
        body.target_status,
        _actor(request),
        note=body.note,
        expected_revision=body.expected_revision,
    )


@router.post("/policies/{policy_id}/attest")
async def attest_policy(
    request: Request, policy_id: str, body: schemas.SecurityPolicyAttestIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.attest_policy,
        policy_id[:80],
        body.subject,
        body.statement,
        _actor(request),
        body.expected_revision,
    )


@router.post("/policies/{policy_id}/review")
async def trigger_policy_review(
    request: Request, policy_id: str, body: schemas.SecurityReviewTriggerIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.trigger_policy_review,
        policy_id[:80],
        body.reason,
        _actor(request),
        body.expected_revision,
    )


@router.get("/incidents")
async def list_security_incidents(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    records = await _ops_call(ops, ops.list_incidents)
    from .incident_attachment_projection import project_incident_records

    return {
        "incidents": await run_in_threadpool(
            project_incident_records, request, records, "security"
        )
    }


@router.post("/incidents", status_code=201)
async def open_security_incident(
    request: Request, body: schemas.SecurityIncidentIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_record_call(
        ops,
        ops.open_incident,
        body.title,
        severity=body.severity,
        description=body.description,
        mitre_techniques=body.mitre_techniques,
        clock_ids=body.clock_ids,
        custom_clocks=body.custom_clocks,
        reported_by=_actor(request),
        discovered_at=body.discovered_at,
    )
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


@router.get("/incidents/{incident_id}")
async def get_security_incident(request: Request, incident_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_incident, incident_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such incident")
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


@router.post("/incidents/{incident_id}/phase")
async def record_incident_phase(
    request: Request,
    incident_id: str,
    body: schemas.SecurityIncidentPhaseIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_record_call(
        ops,
        ops.record_incident_phase,
        incident_id[:80],
        body.phase,
        body.note,
        _actor(request),
        body.expected_revision,
        occurred_at=body.occurred_at,
    )
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


@router.post("/incidents/{incident_id}/clock")
async def start_incident_clock(
    request: Request,
    incident_id: str,
    body: schemas.SecurityIncidentClockIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_record_call(
        ops,
        ops.start_incident_clock,
        incident_id[:80],
        body.clock_id,
        body.anchor_at,
        _actor(request),
        body.expected_revision,
    )
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


@router.post("/incidents/{incident_id}/notification")
async def decide_incident_notification(
    request: Request,
    incident_id: str,
    body: schemas.SecurityIncidentNotifyIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_record_call(
        ops,
        ops.decide_incident_notification,
        incident_id[:80],
        body.clock_id,
        body.notifiable,
        body.rationale,
        _actor(request),
        body.expected_revision,
    )
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


@router.post("/incidents/{incident_id}/close")
async def close_security_incident(
    request: Request,
    incident_id: str,
    body: schemas.SecurityIncidentCloseIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_record_call(
        ops,
        ops.close_incident,
        incident_id[:80],
        body.summary,
        _actor(request),
        body.expected_revision,
    )
    from .incident_attachment_projection import project_incident_record

    return await run_in_threadpool(
        project_incident_record, request, record, "security"
    )


# Audit engagements ---------------------------------------------------------

@router.get("/audits")
async def list_audits(request: Request) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return {"audits": await _ops_call(ops, ops.list_audit_engagements)}


@router.post("/audits", status_code=201)
async def create_audit(
    request: Request, body: schemas.SecurityEngagementIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.create_audit_engagement,
        body.name,
        body.framework,
        body.scope,
        body.owner,
        due_at=body.due_at,
        created_by=_actor(request),
    )


@router.get("/audits/{audit_id}")
async def get_audit(request: Request, audit_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    record = await _ops_call(ops, ops.get_audit_engagement, audit_id[:80])
    if record is None:
        raise HTTPException(status_code=404, detail="no such audit engagement")
    return record


@router.post("/audits/{audit_id}/evidence-requests")
async def add_evidence_request(
    request: Request,
    audit_id: str,
    body: schemas.SecurityEvidenceRequestIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.add_evidence_request,
        audit_id[:80],
        body.description,
        body.owner,
        body.due_at,
        control_ids=body.control_ids,
        requested_by=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.patch("/audits/{audit_id}/evidence-requests")
async def update_evidence_request(
    request: Request,
    audit_id: str,
    body: schemas.SecurityEvidenceRequestUpdateIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.update_evidence_request,
        audit_id[:80],
        body.request_id,
        body.status,
        evidence_ids=body.evidence_ids,
        updated_by=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/audits/{audit_id}/control-tests")
async def record_control_test(
    request: Request,
    audit_id: str,
    body: schemas.SecurityControlTestIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.record_control_test,
        audit_id[:80],
        body.control_id,
        body.procedure,
        body.result,
        evidence_ids=body.evidence_ids,
        tested_by=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/audits/{audit_id}/findings")
async def add_audit_finding(
    request: Request,
    audit_id: str,
    body: schemas.SecurityAuditFindingIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.add_audit_finding,
        audit_id[:80],
        body.title,
        body.severity,
        control_ids=body.control_ids,
        owner=body.owner,
        due_at=body.due_at,
        created_by=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.patch("/audits/{audit_id}/findings")
async def update_audit_finding(
    request: Request,
    audit_id: str,
    body: schemas.SecurityAuditFindingUpdateIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.update_audit_finding,
        audit_id[:80],
        body.finding_id,
        body.status,
        _actor(request),
        body.expected_revision,
    )


@router.patch("/audits/{audit_id}/status")
async def update_audit_status(
    request: Request,
    audit_id: str,
    body: schemas.SecurityEngagementStatusIn,
) -> dict:
    require_permission(request, "operate")
    ops = _ops()
    return await _ops_record_call(
        ops,
        ops.update_audit_engagement_status,
        audit_id[:80],
        body.status,
        _actor(request),
        body.expected_revision,
    )


# Defensive-hunter helpers --------------------------------------------------

_MAX_ENVIRONMENT_BATCH_BYTES = 16 * 1024 * 1024
_PLATFORM_STATUSES = {
    "open", "triaged", "investigating", "resolved", "false_positive", "closed",
}
_INVESTIGATION_STATUSES = {
    "open", "triaged", "investigating", "contained", "resolved", "closed",
}


def _bounded_json(value: object, *, maximum: int, label: str) -> None:
    """Reject oversized already-decoded request structures before analysis."""
    try:
        size = len(json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{label} is not valid JSON") from exc
    if size > maximum:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the {maximum // (1024 * 1024)} MiB limit",
        )


def _platform_store():
    from maverick.paths import data_dir
    from maverick.platform_hunt import HuntStore

    return HuntStore(data_dir("platform_hunt", "records.sqlite3"))


def _environment_store():
    from maverick.env_hunt import HuntStore
    from maverick.paths import data_dir

    return HuntStore(data_dir("env_hunt", "records.sqlite3"))


def _platform_module():
    from maverick import platform_hunt

    if not platform_hunt.enabled():
        raise HTTPException(
            status_code=403,
            detail="platform threat hunting is disabled ([threat_hunt] enable)",
        )
    return platform_hunt


def _environment_module():
    from maverick import env_hunt

    if not env_hunt.enabled():
        raise HTTPException(
            status_code=403,
            detail="environment threat hunting is disabled ([env_hunt] enable)",
        )
    return env_hunt


_hunter_scheduler_lock = threading.Lock()
_hunter_scheduler_stop: threading.Event | None = None
_hunter_scheduler_thread: threading.Thread | None = None


def _hunter_poll_seconds(section: object, *, default: float = 300.0) -> float:
    if not isinstance(section, dict):
        return default
    raw = section.get("poll_seconds", default)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return default
    return max(30.0, min(float(raw), 86_400.0))


def _hunter_scheduler_tenant_cycle(owner: str, global_config: dict) -> None:
    """Run one bounded hunter turn in the explicitly pinned tenant namespace."""
    from maverick.config import load_config

    config = load_config() or {}
    now = time.time()
    global_platform = global_config.get("threat_hunt")
    platform = config.get("threat_hunt")
    if isinstance(global_platform, dict) and global_platform.get("enable") is True:
        platform = platform if isinstance(platform, dict) else global_platform
        interval = _hunter_poll_seconds(platform)
        store = _platform_store()
        if store.try_acquire_scheduler_lease(
            "platform", owner=owner, lease_seconds=interval, now=now,
        ):
            hours = max(1, min(24 * 365, int(interval // 3600) + 1))
            try:
                _run_platform_scan(
                    schemas.PlatformHuntScanIn(since_hours=hours),
                    "system:platform-hunter-scheduler",
                )
            except Exception as exc:  # failure-policy: visible_degradation
                log.warning("platform hunter scheduler turn failed: %s", type(exc).__name__)
    global_environment = global_config.get("env_hunt")
    environment = config.get("env_hunt")
    if (
        not isinstance(global_environment, dict)
        or global_environment.get("enable") is not True
    ):
        return
    environment = environment if isinstance(environment, dict) else global_environment
    interval = _hunter_poll_seconds(environment)
    env_hunt = _environment_module()
    factory = _configured_environment_connector_factory(env_hunt)
    store = _environment_store()
    poll_limit = environment.get("poll_limit", 1000)
    if isinstance(poll_limit, bool) or not isinstance(poll_limit, int):
        poll_limit = 1000
    poll_limit = max(1, min(poll_limit, 1000))
    for connector in factory.available_names():
        if not store.try_acquire_scheduler_lease(
            f"environment:{connector}",
            owner=owner,
            lease_seconds=interval,
            now=now,
        ):
            continue
        try:
            _run_environment_ingest(
                schemas.EnvironmentIngestIn(
                    connector=connector,
                    start=max(0.0, now - interval),
                    end=now,
                    limit=poll_limit,
                ),
                "system:environment-hunter-scheduler",
            )
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning(
                "environment hunter scheduler turn failed for %s: %s",
                connector,
                type(exc).__name__,
            )


def _hunter_scheduler_cycle(owner: str) -> None:
    """Run one cycle across the shared floor and every active tenant."""
    from maverick.config import config_source_errors, load_global_config

    from .automation_queue import _run_for_active_tenants

    global_config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("security hunter scheduler skipped: global config is unreadable")
        return
    complete = _run_for_active_tenants(
        "security hunter scheduler",
        lambda: _hunter_scheduler_tenant_cycle(owner, global_config),
    )
    if not complete:
        log.warning("security hunter scheduler had one or more degraded tenant turns")


def _hunter_scheduler_loop(stop: threading.Event, owner: str) -> None:
    while not stop.is_set():
        try:
            _hunter_scheduler_cycle(owner)
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("security hunter scheduler cycle failed: %s", type(exc).__name__)
        stop.wait(30.0)


def start_hunter_scheduler() -> bool:
    """Start the off-by-default, lease-coordinated production hunter loop."""
    from maverick.config import config_source_errors, load_global_config

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        return False
    if not any(
        isinstance(config.get(name), dict) and config[name].get("enable") is True
        for name in ("threat_hunt", "env_hunt")
    ):
        return False
    global _hunter_scheduler_stop, _hunter_scheduler_thread
    with _hunter_scheduler_lock:
        if _hunter_scheduler_thread is not None and _hunter_scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(
            target=_hunter_scheduler_loop,
            args=(stop, f"dashboard:{uuid.uuid4().hex}"),
            name="security-hunter-scheduler",
            daemon=True,
        )
        _hunter_scheduler_stop = stop
        _hunter_scheduler_thread = worker
        worker.start()
        return True


def stop_hunter_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; retain a stopping worker until its exit is observed."""
    global _hunter_scheduler_stop, _hunter_scheduler_thread
    with _hunter_scheduler_lock:
        stop = _hunter_scheduler_stop
        worker = _hunter_scheduler_thread
        if stop is not None:
            stop.set()
    if stop is None or worker is None:
        return False
    if not wait:
        return not worker.is_alive()
    worker.join(max(0.0, min(float(timeout), 30.0)))
    if worker.is_alive():
        return False
    with _hunter_scheduler_lock:
        if _hunter_scheduler_thread is worker:
            _hunter_scheduler_stop = None
            _hunter_scheduler_thread = None
    return True


async def _hunt_call(module, fn: Callable, *args, **kwargs):
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except module.RevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except module.RecordNotFound as exc:
        raise HTTPException(status_code=404, detail="no such hunter record") from exc
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _evidence_refs(rows: list[dict] | tuple[dict, ...]):
    from maverick.platform_hunt import EvidenceRef

    return tuple(EvidenceRef(
        event_id=str(row["event_id"]),
        source=str(row["source"]),
        observed_at=float(row["observed_at"]),
        sha256=str(row["sha256"]),
        quote=str(row.get("quote", "")),
    ) for row in rows)


def _finding_record(record: dict):
    from maverick.platform_hunt import Finding

    return Finding(
        finding_id=str(record["finding_id"]),
        rule_id=str(record["rule_id"]),
        title=str(record["title"]),
        severity=str(record["severity"]),
        verdict=str(record["verdict"]),
        mitre_techniques=tuple(str(item) for item in record.get("mitre_techniques", ())),
        evidence=_evidence_refs(record.get("evidence", ())),
        score=int(record["score"]),
        suggested_containment=str(record.get("suggested_containment", "")),
        status=str(record.get("status", "open")),
        created_at=float(record.get("created_at", 0.0)),
        metadata=dict(record.get("metadata") or {}),
    )


def _audit_media_snapshot(paths, audit_dir) -> tuple[tuple[str, bool, int, str], ...]:
    """Commit the exact audit media set consumed by verification and hunting."""
    from pathlib import Path

    directory = Path(audit_dir)
    candidates = {Path(path) for path in paths}
    if directory.exists() and directory.is_dir():
        candidates.update(directory.glob("*.ndjson"))
    candidates.update({directory / "anchors.ndjson", directory / ".anchors.required",
                       directory / ".anchors.highwater.json"})
    snapshot = []
    for path in sorted(candidates, key=lambda item: item.name):
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            snapshot.append((path.name, False, 0, ""))
        except OSError:
            snapshot.append((path.name, True, -1, "unreadable"))
        else:
            snapshot.append((path.name, True, len(raw), hashlib.sha256(raw).hexdigest()))
    return tuple(snapshot)


def _capture_verified_audit_rows(
    paths, audit_dir,
) -> tuple[list[dict], tuple[tuple[str, bool, int, str], ...]]:
    """Authenticate and parse identity-bound bytes, returning their commitment.

    Closed segments are checked against the exact signed anchor snapshot. The
    live day is unanchored by design, but every captured row is still verified
    from the exact bytes read through the custody helper.  The returned media
    commitment is deliberately computed from those same bytes; callers bind it
    into their before/read/verify comparison so a same-path ABA rollback cannot
    make rows from one valid signed snapshot appear to belong to another.
    """
    from pathlib import Path

    from maverick.audit.worm import (
        _read_custodied_file,
        _verified_chain_records,
        _verified_source_snapshot,
    )

    directory = Path(audit_dir)
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    normalized = tuple(sorted({Path(path) for path in paths}, key=str))
    closed = [path for path in normalized if path.stem < today]
    closed_snapshot = _verified_source_snapshot(directory, closed) if closed else {}
    rows: list[dict] = []
    captured_media: list[tuple[str, bool, int, str]] = []
    for path in normalized:
        raw = (
            closed_snapshot[path.name]
            if path.stem < today
            else _read_custodied_file(path, mode=0o600)
        )
        captured_media.append(
            (path.name, True, len(raw), hashlib.sha256(raw).hexdigest())
        )
        rows.extend(_verified_chain_records(raw))
    return rows, tuple(captured_media)


def _bind_captured_audit_snapshot(
    observed: tuple[tuple[str, bool, int, str], ...],
    captured: tuple[tuple[str, bool, int, str], ...],
) -> tuple[tuple[str, bool, int, str], ...]:
    """Replace selected-path observations with the exact bytes rows came from.

    ``observed`` also commits the anchor ledger, deletion marker, and audit files
    outside the selected window.  Only selected day-file entries are replaced;
    this retains that wider media-set check while binding verdict inputs to the
    identity-bound handles consumed by :func:`_capture_verified_audit_rows`.
    """
    captured_by_name = {entry[0]: entry for entry in captured}
    if len(captured_by_name) != len(captured):
        raise RuntimeError("captured audit media contains duplicate names")
    observed_names = {entry[0] for entry in observed}
    if not set(captured_by_name).issubset(observed_names):
        raise RuntimeError("captured audit media is absent from the observed set")
    return tuple(captured_by_name.get(entry[0], entry) for entry in observed)


def _audit_window(
    hours: int,
) -> tuple[list[dict], list, Any, float, float, tuple, tuple]:
    """Load a bounded tenant-local audit window and its signed media paths."""
    from maverick.audit.export import audit_event_paths
    from maverick.audit.reader import resolve_audit_dir
    from maverick.paths import current_tenant_id

    now = time.time()
    cutoff = now - hours * 3600.0
    baseline_cutoff = cutoff - 30 * 86400.0
    since_day = dt.datetime.fromtimestamp(
        baseline_cutoff, tz=dt.timezone.utc,
    ).date().isoformat()
    tenant = current_tenant_id()
    audit_dir = resolve_audit_dir(tenant)
    paths = audit_event_paths(since=since_day, tenant=tenant)
    snapshot_before = _audit_media_snapshot(paths, audit_dir)
    try:
        captured, captured_media = _capture_verified_audit_rows(paths, audit_dir)
        snapshot_after_read = _bind_captured_audit_snapshot(
            _audit_media_snapshot(paths, audit_dir), captured_media,
        )
    except Exception:  # failure-policy: fail_closed
        captured = []
        snapshot_after_read = (("audit-evidence", True, -1, "verification_error"),)
    rows = []
    for row in captured:
        try:
            observed = float(row.get("ts", 0.0))
        except (TypeError, ValueError):
            continue
        if baseline_cutoff <= observed <= now + 300:
            rows.append(row)
    # Preserve the newest bounded slice when a very busy deployment exceeds it.
    rows = sorted(rows, key=lambda item: float(item.get("ts", 0.0)))[-50_000:]
    return (
        rows,
        paths,
        audit_dir,
        cutoff,
        baseline_cutoff,
        snapshot_before,
        snapshot_after_read,
    )


def _budget_receipt_hunt_rows() -> tuple[list[dict[str, Any]], list[str]]:
    """Load only cryptographically verified spend receipts as budget evidence.

    Mutable ``EpisodeSpend`` rows do not carry the per-run cap and are not an
    authority boundary.  The receipt ledger commits both actual spend and the
    configured cap context, so budget verdicts are emitted only from a complete,
    valid HMAC chain.  Failures are surfaced without leaking its local path.
    """
    from maverick import budget_receipts

    path = budget_receipts.receipts_path()
    if not path.exists():
        return [], []
    try:
        key = budget_receipts.resolve_key()
        chain = budget_receipts.verify_chain(path, key)
    except Exception as exc:  # failure-policy: visible_degradation
        return [], [f"budget_receipts:{type(exc).__name__}"]
    if not chain.ok:
        return [], ["budget_receipts:chain_invalid"]
    try:
        lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        # ``verify_chain`` and this read are separate filesystem operations.
        # Revalidate the exact snapshot used for verdicts, then require a
        # second full-chain pass with the same count.  A concurrent append is
        # retried on the next scheduler turn; a modified snapshot never
        # becomes evidence merely because an earlier read verified.
        if len(lines) != chain.count:
            return [], ["budget_receipts:snapshot_changed"]
        previous_hash: str | None = None
        for line in lines:
            if budget_receipts.verify(line, key) != budget_receipts.VALID:
                return [], ["budget_receipts:snapshot_invalid"]
            receipt = json.loads(line)
            if receipt["payload"].get("prev_receipt_hash") != previous_hash:
                return [], ["budget_receipts:snapshot_invalid"]
            previous_hash = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
        confirmed = budget_receipts.verify_chain(path, key)
        if not confirmed.ok:
            return [], ["budget_receipts:chain_invalid"]
        if confirmed.count != len(lines):
            return [], ["budget_receipts:snapshot_changed"]
        rows: list[dict[str, Any]] = []
        for index, line in enumerate(lines[-50_000:]):
            receipt = json.loads(line)
            payload = receipt["payload"]
            caps = payload.get("budget_caps")
            limit = caps.get("max_dollars") if isinstance(caps, dict) else None
            used = payload.get("total_dollars")
            if (
                isinstance(used, bool)
                or not isinstance(used, (int, float))
                or isinstance(limit, bool)
                or not isinstance(limit, (int, float))
            ):
                continue
            rows.append({
                "event_id": (
                    f"budget_receipt_"
                    f"{hashlib.sha256(line.encode()).hexdigest()[:24]}"
                ),
                "kind": "budget",
                "observed_at": payload.get("minted_at", 0.0),
                "actor": "system:budget-receipts",
                "goal_id": str(payload.get("goal_id", "")),
                "used": float(used),
                "limit": float(limit),
                "outcome": "exceeded" if float(used) > float(limit) else "within_limit",
                "receipt_index": max(0, len(lines) - 50_000) + index,
            })
    except Exception as exc:  # failure-policy: visible_degradation
        return [], [f"budget_receipts:{type(exc).__name__}"]
    return rows, []


def _collect_platform_events(hours: int):
    from maverick.platform_hunt import collect_lightwork_events

    (
        audit_rows,
        paths,
        audit_dir,
        cutoff,
        baseline_cutoff,
        snapshot_before,
        snapshot_after_read,
    ) = _audit_window(hours)
    budget_rows, degraded = _budget_receipt_hunt_rows()
    events = list(collect_lightwork_events(
        audit_events=audit_rows,
        budget_receipts=budget_rows,
    ))
    current = [event for event in events if cutoff <= event.observed_at]
    baseline = [
        event for event in events
        if baseline_cutoff <= event.observed_at < cutoff
    ]
    return (
        current,
        baseline,
        paths,
        audit_dir,
        degraded,
        snapshot_before,
        snapshot_after_read,
    )


def _verified_audit_chain(
    platform_hunt,
    paths,
    audit_dir,
    snapshot_before,
    snapshot_after_read,
    *,
    custody_witness_ready: bool = True,
):
    """Verify and consume one identity-bound audit snapshot or fail closed."""
    chain = platform_hunt.verify_audit_chain(paths, audit_dirs=(audit_dir,))
    snapshot_after_verify = _audit_media_snapshot(paths, audit_dir)
    snapshot_stable = snapshot_before == snapshot_after_read == snapshot_after_verify
    if custody_witness_ready and snapshot_stable:
        return chain
    extra_breaks = []
    if not custody_witness_ready:
        extra_breaks.append({
            "path": "audit-custody",
            "line_no": 0,
            "reason": "custody_initialization_failed",
            "detail": "signed audit custody could not be initialized",
        })
    if not snapshot_stable:
        extra_breaks.append({
            "path": "audit-snapshot",
            "line_no": 0,
            "reason": "snapshot_changed",
            "detail": "signed audit media changed during verification",
        })
    return platform_hunt.ChainIntegrityStatus(
        intact=False,
        paths_checked=chain.paths_checked,
        breaks=tuple(chain.breaks) + tuple(extra_breaks),
        checked_at=time.time(),
    )


def _queue_platform_containment(proposal) -> int:
    from maverick.approval_cards import (
        digest,
        encode_operation_approval_detail,
    )

    from ._shared import _world

    payload = {
        "proposal_id": proposal.proposal_id,
        "action": proposal.action,
        "scope": proposal.scope,
        "reason": proposal.reason,
        "evidence_ids": [item.event_id for item in proposal.evidence],
    }
    detail = encode_operation_approval_detail(
        action="security.platform_containment",
        summary=f"Review platform containment proposal {proposal.action}",
        target_label=f"Platform scope: {proposal.scope}"[:500],
        target={"proposal_id": proposal.proposal_id, "scope": proposal.scope},
        parameters=payload,
        parameter_summary=[
            f"Containment action: {proposal.action}",
            f"Proposal SHA-256: {digest(payload)}",
            f"Cited evidence events: {len(proposal.evidence)}",
        ],
        actor="system:platform_hunt",
        role="security_operator",
        input_versions={"proposal_sha256": digest(payload)},
        known_effects=[
            "Records a human decision for the exact cited containment proposal."
        ],
        unresolved_assumptions=[
            "The platform hunter has no containment executor in this workflow."
        ],
        before="The containment proposal remains inert and pending review.",
        after="The reviewed containment proposal has a recorded decision.",
        irreversible=False,
        ttl_seconds=24 * 3600,
    )
    return int(_world().create_approval(
        "security.platform_containment",
        risk="high",
        scope=proposal.scope,
        detail=detail,
        provenance="security.platform_hunt.v1",
        requested_by="system:platform_hunt",
    ))


def _ensure_platform_finding(store, finding, *, actor: str) -> tuple[bool, bool, int | None]:
    """Idempotently persist a finding, cited investigation, and inert proposal."""
    from maverick.platform_hunt import (
        ContainmentProposal,
        Investigation,
        RevisionConflict,
        deterministic_id,
    )

    created_finding = False
    if store.get_finding(finding.finding_id) is None:
        try:
            store.create_finding(finding, actor=actor)
            created_finding = True
        except RevisionConflict:
            pass
    investigation_id = deterministic_id("inv", "platform", finding.finding_id)
    proposal = ContainmentProposal.build(
        "platform_containment_review",
        finding.finding_id,
        finding.suggested_containment or finding.verdict,
        finding.evidence,
    )
    created_investigation = False
    investigation = store.get_investigation(investigation_id)
    if investigation is None:
        model = Investigation(
            investigation_id=investigation_id,
            title=finding.title,
            finding_ids=(finding.finding_id,),
            evidence=finding.evidence,
            summary=(
                f"Deterministic {finding.rule_id} verdict with cited signed telemetry. "
                "Human validation is required before containment."
            ),
            containment=proposal,
            created_at=finding.created_at,
        )
        try:
            investigation = store.create_investigation(model, actor=actor)
            created_investigation = True
        except RevisionConflict:
            investigation = store.get_investigation(investigation_id)
    approval_id = None
    if investigation is not None:
        raw_approval = investigation.get("approval_id")
        approval_id = int(raw_approval) if raw_approval else None
        if approval_id is None:
            approval_id = _queue_platform_containment(proposal)
            try:
                store.update_investigation(
                    investigation_id,
                    {"approval_id": approval_id},
                    expected_revision=int(investigation["revision"]),
                    actor=actor,
                )
            except RevisionConflict:
                # Another scan won the race. Its exact deterministic proposal is
                # authoritative; the redundant pending approval remains inert.
                pass
    return created_finding, created_investigation, approval_id


def _run_platform_scan(body: schemas.PlatformHuntScanIn, actor: str) -> dict:
    platform_hunt = _platform_module()
    store = _platform_store()
    custody_witness_ready = store.ensure_audit_custody_witness()
    (
        events,
        baseline,
        paths,
        audit_dir,
        degraded,
        snapshot_before,
        snapshot_after_read,
    ) = _collect_platform_events(body.since_hours)
    chain_status = _verified_audit_chain(
        platform_hunt,
        paths,
        audit_dir,
        snapshot_before,
        snapshot_after_read,
        custody_witness_ready=custody_witness_ready,
    )
    report = platform_hunt.scan(
        events,
        baseline_events=baseline,
        chain_status=chain_status,
    )
    if report.audited_findings != len(report.findings):
        raise RuntimeError("platform detection audit was not accepted")
    finding_count = investigation_count = approval_count = 0
    for finding in report.findings:
        try:
            finding_created, investigation_created, approval_id = (
                _ensure_platform_finding(store, finding, actor=actor)
            )
        except Exception as exc:  # failure-policy: visible_degradation
            degraded.append(f"persist:{finding.finding_id}:{type(exc).__name__}")
            continue
        finding_count += int(finding_created)
        investigation_count += int(investigation_created)
        approval_count += int(approval_id is not None and investigation_created)
    return {
        "events_scanned": report.events_scanned,
        "baseline_events": len(baseline),
        "findings_detected": len(report.findings),
        "findings_created": finding_count,
        "investigations_created": investigation_count,
        "approvals_queued": approval_count,
        "audited_findings": report.audited_findings,
        "chain_status": _jsonable(report.chain_status),
        "degraded_sources": degraded,
    }


def _platform_summary(*, include_records: bool) -> dict:
    platform_hunt = _platform_module()
    store = _platform_store()
    findings = store.list_findings(limit=10_000)
    investigations = store.list_investigations(limit=10_000)
    (
        _rows,
        paths,
        audit_dir,
        _cutoff,
        _baseline,
        snapshot_before,
        snapshot_after_read,
    ) = _audit_window(24 * 30)
    chain = _verified_audit_chain(
        platform_hunt,
        paths,
        audit_dir,
        snapshot_before,
        snapshot_after_read,
    )
    result = {
        "enabled": True,
        "open_findings": sum(
            row.get("status") not in {"resolved", "false_positive", "closed"}
            for row in findings
        ),
        "investigation_count": len(investigations),
        "chain_status": _jsonable(chain),
        "journal_intact": not store.verify_journal(),
        "pending_audit_records": store.pending_audit_count(),
    }
    if include_records:
        result.update({"findings": findings, "investigations": investigations})
    return result


# Platform threat hunter ----------------------------------------------------

@router.get("/threats/stats")
async def platform_threat_stats(request: Request) -> dict:
    require_permission(request, "view")
    _platform_module()
    return await run_in_threadpool(_platform_summary, include_records=False)


@router.get("/threats/summary")
async def platform_threat_summary(request: Request) -> dict:
    require_permission(request, "operate")
    _platform_module()
    return await run_in_threadpool(_platform_summary, include_records=True)


@router.post("/threats/scan")
async def run_platform_threat_scan(
    request: Request, body: schemas.PlatformHuntScanIn,
) -> dict:
    require_permission(request, "operate")
    _platform_module()
    try:
        return await run_in_threadpool(_run_platform_scan, body, _actor(request))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/threats/findings/{finding_id}")
async def get_platform_finding(request: Request, finding_id: str) -> dict:
    require_permission(request, "operate")
    _platform_module()
    record = await run_in_threadpool(_platform_store().get_finding, finding_id[:120])
    if record is None:
        raise HTTPException(status_code=404, detail="no such finding")
    return record


@router.patch("/threats/findings/{finding_id}")
async def update_platform_finding(
    request: Request, finding_id: str, body: schemas.HuntRecordUpdateIn,
) -> dict:
    require_permission(request, "operate")
    module = _platform_module()
    changes = dict(body.changes)
    if set(changes) != {"status"} or changes.get("status") not in _PLATFORM_STATUSES:
        raise HTTPException(status_code=422, detail="only a valid finding status may change")
    return await _hunt_call(
        module,
        _platform_store().update_finding,
        finding_id[:120],
        changes,
        expected_revision=body.expected_revision,
        actor=_actor(request),
    )


@router.get("/threats/investigations/{investigation_id}")
async def get_platform_investigation(
    request: Request, investigation_id: str,
) -> dict:
    require_permission(request, "operate")
    _platform_module()
    record = await run_in_threadpool(
        _platform_store().get_investigation, investigation_id[:120],
    )
    if record is None:
        raise HTTPException(status_code=404, detail="no such investigation")
    return record


@router.patch("/threats/investigations/{investigation_id}")
async def update_platform_investigation(
    request: Request,
    investigation_id: str,
    body: schemas.HuntRecordUpdateIn,
) -> dict:
    require_permission(request, "operate")
    module = _platform_module()
    changes = dict(body.changes)
    if not changes or not set(changes).issubset({"status", "assignee", "summary"}):
        raise HTTPException(status_code=422, detail="unsupported investigation change")
    if "status" in changes and changes["status"] not in _INVESTIGATION_STATUSES:
        raise HTTPException(status_code=422, detail="invalid investigation status")
    for key in ("assignee", "summary"):
        if key in changes and len(str(changes[key])) > (200 if key == "assignee" else 8_000):
            raise HTTPException(status_code=422, detail=f"{key} is too long")
    return await _hunt_call(
        module,
        _platform_store().update_investigation,
        investigation_id[:120],
        changes,
        expected_revision=body.expected_revision,
        actor=_actor(request),
    )


@router.post("/threats/investigations", status_code=201)
async def create_platform_investigation(
    request: Request, body: schemas.PlatformInvestigationIn,
) -> dict:
    require_permission(request, "operate")
    module = _platform_module()
    store = _platform_store()
    findings = []
    for finding_id in dict.fromkeys(body.finding_ids):
        row = await run_in_threadpool(store.get_finding, finding_id[:120])
        if row is None:
            raise HTTPException(status_code=404, detail=f"no such finding: {finding_id}")
        findings.append(_finding_record(row))
    from maverick.platform_hunt import Investigation, deterministic_id

    evidence = {
        item.event_id: item for finding in findings for item in finding.evidence
    }
    model = Investigation(
        investigation_id=deterministic_id(
            "inv", "platform", tuple(sorted(item.finding_id for item in findings)),
        ),
        title=body.title,
        finding_ids=tuple(sorted(item.finding_id for item in findings)),
        evidence=tuple(evidence[key] for key in sorted(evidence)),
        summary=body.summary,
        created_at=max(item.created_at for item in findings),
    )
    return await _hunt_call(
        module, store.create_investigation, model, actor=_actor(request),
    )


@router.post("/threats/investigations/{investigation_id}/containment")
async def propose_platform_containment(
    request: Request,
    investigation_id: str,
    body: schemas.PlatformContainmentIn,
) -> dict:
    require_permission(request, "operate")
    module = _platform_module()
    store = _platform_store()
    row = await run_in_threadpool(store.get_investigation, investigation_id[:120])
    if row is None:
        raise HTTPException(status_code=404, detail="no such investigation")
    from maverick.platform_hunt import ContainmentProposal

    proposal = ContainmentProposal.build(
        body.action,
        body.scope,
        body.reason,
        _evidence_refs(row.get("evidence", ())),
    )
    updated = await _hunt_call(
        module,
        store.propose_containment,
        investigation_id[:120],
        proposal,
        expected_revision=body.expected_revision,
        actor=_actor(request),
    )
    try:
        approval_id = await run_in_threadpool(_queue_platform_containment, proposal)
        updated = await _hunt_call(
            module,
            store.update_investigation,
            investigation_id[:120],
            {"approval_id": approval_id},
            expected_revision=int(updated["revision"]),
            actor=_actor(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        return {
            "investigation": updated,
            "approval_queued": False,
            "detail": f"proposal stored but approval queue degraded: {type(exc).__name__}",
        }
    return {"investigation": updated, "approval_queued": True, "approval_id": approval_id}


# Environment threat hunter -------------------------------------------------

_environment_registry_lock = threading.Lock()
_response_executor_registries: dict[str, Any] = {}
_environment_connector_transports: dict[tuple[str, str], Callable] = {}
_environment_enrichment_providers: dict[tuple[str, str], Any] = {}


def _environment_tenant_binding(tenant: str | None = None) -> str:
    """Return the exact canonical tenant binding for one trusted adapter.

    An empty string is the legacy single-tenant/root namespace.  Tenant-scoped
    requests never fall back to it: a credential-owning transport, enrichment
    provider, or mutating executor registered for one customer must not become
    ambient authority for another customer merely because both use the same
    connector name.
    """
    from maverick.paths import canonical_tenant_id, current_tenant_id_strict

    selected = current_tenant_id_strict() if tenant is None else tenant
    return canonical_tenant_id(selected) if selected else ""


def environment_response_registry(*, tenant: str | None = None):
    """Process-wide vendor-neutral executor extension point.

    Lightwork intentionally registers no mutating executor. Deployments may
    register a narrow adapter during trusted startup; the REST API can only
    select one of those already-registered adapters after all governance gates.
    """
    from maverick.env_hunt import ResponseExecutorRegistry

    binding = _environment_tenant_binding(tenant)
    with _environment_registry_lock:
        registry = _response_executor_registries.get(binding)
        if registry is None:
            registry = ResponseExecutorRegistry()
            _response_executor_registries[binding] = registry
        return registry


def register_environment_connector_transport(
    name: str, transport: Callable, *, tenant: str | None = None,
) -> None:
    """Trusted-startup hook for credential-owning, read-only connector clients."""
    from maverick import env_hunt

    normalized = str(name).strip().lower()
    if normalized not in env_hunt.CONNECTOR_NAMES:
        raise KeyError(f"unknown environment connector {normalized}")
    if not callable(transport):
        raise TypeError("environment connector transport must be callable")
    binding = _environment_tenant_binding(tenant)
    key = (binding, normalized)
    with _environment_registry_lock:
        if key in _environment_connector_transports:
            raise ValueError(
                f"environment connector {normalized} is already registered for tenant"
            )
        _environment_connector_transports[key] = transport


def register_environment_enrichment_provider(
    provider: Any, *, tenant: str | None = None,
) -> None:
    """Trusted-startup hook for a read-only, allowlisted enrichment adapter."""
    from maverick import env_hunt

    if not isinstance(provider, env_hunt.EnrichmentProvider):
        raise TypeError("environment enrichment provider is incompatible")
    normalized = str(provider.name).strip().lower()
    if not normalized or len(normalized) > 120:
        raise ValueError("environment enrichment provider requires a short name")
    binding = _environment_tenant_binding(tenant)
    key = (binding, normalized)
    with _environment_registry_lock:
        if key in _environment_enrichment_providers:
            raise ValueError(
                f"environment enrichment provider {normalized} is already registered for tenant"
            )
        _environment_enrichment_providers[key] = provider


def _configured_environment_connector_factory(env_hunt):
    """Build a fresh policy snapshot while retaining only trusted transports."""
    factory = env_hunt.ConnectorFactoryRegistry()
    binding = _environment_tenant_binding()
    with _environment_registry_lock:
        transports = tuple(
            (name, transport)
            for (registered_tenant, name), transport
            in _environment_connector_transports.items()
            if registered_tenant == binding
        )
    for name, transport in sorted(transports):
        factory.register_transport(name, transport)
    return factory


def _configured_environment_enrichment_providers() -> tuple[tuple[Any, ...], tuple[str, ...]]:
    from maverick.config import config_source_errors, load_config

    config = load_config() or {}
    if config_source_errors():
        return (), ()
    section = config.get("env_hunt")
    configured = section.get("enrichment_sources") if isinstance(section, dict) else None
    if isinstance(configured, dict):
        allowed = tuple(sorted(
            str(name).strip().lower()
            for name, value in configured.items()
            if isinstance(value, dict)
            and value.get("enable") is True
            and str(name).strip()
        ))
    elif isinstance(configured, list):
        # Backward compatibility for installer versions that emitted an inline
        # list. New configs use explicit enable tables below this section.
        allowed = tuple(sorted({
            str(name).strip().lower()
            for name in configured
            if isinstance(name, str) and str(name).strip()
        }))
    else:
        allowed = ()
    binding = _environment_tenant_binding()
    with _environment_registry_lock:
        registered = {
            name: provider
            for (registered_tenant, name), provider
            in _environment_enrichment_providers.items()
            if registered_tenant == binding
        }
    providers = tuple(
        registered[name]
        for name in allowed
        if name in registered
    )
    return providers, allowed


def _connector_for_batch(env_hunt, name: str, rows: list[dict]):
    connector_types = {
        "cloudtrail": env_hunt.CloudTrailConnector,
        "guardduty": env_hunt.GuardDutyConnector,
        "syslog": env_hunt.SyslogConnector,
        "edr": env_hunt.EDRConnector,
        "splunk": env_hunt.SplunkConnector,
        "elastic": env_hunt.ElasticConnector,
        "sentinel": env_hunt.SentinelConnector,
        "kubernetes_audit": env_hunt.KubernetesAuditConnector,
        "okta": env_hunt.OktaConnector,
        "entra": env_hunt.EntraConnector,
    }
    try:
        connector_type = connector_types[name]
    except KeyError as exc:
        raise ValueError(f"unsupported connector {name}") from exc

    def transport(_request):
        return iter(rows)

    return connector_type(transport)


def _environment_shield_posture(events, sigma_rules: list[str]) -> bool:
    """Screen hunter inputs when Shield exists; otherwise reduce autonomy.

    The kernel deliberately permits installations without ``maverick-shield``.
    Environment hunting therefore continues deterministic, local detection in
    that posture, but callers must suppress pivots, enrichment, automatic
    playbook proposals, and response execution.  When Shield is installed, any
    block or scanner error fails this batch toward the gate.
    """
    from maverick import shield_policy

    if not shield_policy.shield_available():
        log.warning(
            "environment hunter is running without Shield; reduced autonomy is active"
        )
        return False
    texts = [
        json.dumps(_jsonable(event), sort_keys=True, default=str)
        for event in events
    ]
    texts.extend(str(rule) for rule in sigma_rules)
    chunk = ""
    chunks: list[str] = []
    for text in texts:
        candidate = f"{chunk}\n{text}" if chunk else text
        if len(candidate.encode("utf-8")) <= 256 * 1024:
            chunk = candidate
            continue
        if chunk:
            chunks.append(chunk)
        chunk = text
    if chunk:
        chunks.append(chunk)
    for text in chunks:
        if shield_policy.scan_block(text):
            raise PermissionError("environment telemetry was rejected by Shield")
    return True


def _response_payload(proposal) -> dict:
    return {
        "proposal_id": proposal.proposal_id,
        "proposal_sha256": proposal.digest,
        "action": proposal.action,
        "target": proposal.target,
        "reason": proposal.reason,
        "parameters": proposal.parameters,
        "executor": proposal.executor,
        "evidence_ids": [item.event_id for item in proposal.evidence],
    }


def _environment_response_executor_binding(executor: object) -> dict[str, str]:
    """Return a secret-free stable binding for one mutating adapter."""
    from types import CodeType

    from maverick.approval_cards import ApprovalCardError, digest

    def stable_constant(value):
        if isinstance(value, CodeType):
            return stable_code(value)
        if value is None or type(value) in (bool, int, str, bytes):
            return value.hex() if isinstance(value, bytes) else value
        if isinstance(value, float):
            return {"float": repr(value)}
        if isinstance(value, tuple):
            return [stable_constant(item) for item in value]
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}

    def stable_code(value: CodeType) -> dict:
        return {
            "bytecode": value.co_code.hex(),
            "constants": [stable_constant(item) for item in value.co_consts],
            "names": list(value.co_names),
            "argcount": value.co_argcount,
            "kwonlyargcount": value.co_kwonlyargcount,
        }

    name = str(getattr(executor, "name", "")).strip().lower()
    execute_method = getattr(type(executor), "execute", None)
    code = getattr(execute_method, "__code__", None)
    implementation = {
        "type": f"{type(executor).__module__}.{type(executor).__qualname__}",
        "execute_code_sha256": digest(
            stable_code(code) if code is not None else {"state": "no_python_code"}
        ),
    }
    revision = str(
        getattr(executor, "approval_revision", None)
        or getattr(executor, "revision", None)
        or getattr(executor, "version", None)
        or "unversioned"
    ).strip()
    declared_digest = getattr(executor, "approval_credential_sha256", None)
    if callable(declared_digest):
        declared_digest = declared_digest()
    if declared_digest is None:
        credential_sha256 = digest({"state": "not_declared"})
    else:
        credential_sha256 = str(declared_digest).strip().lower()
        if (
            len(credential_sha256) != 64
            or any(char not in "0123456789abcdef" for char in credential_sha256)
        ):
            raise ApprovalCardError(
                "response executor credential binding must be a SHA-256 digest"
            )
    return {
        "executor": name,
        "implementation_sha256": digest(implementation),
        "revision": revision,
        "credential_sha256": credential_sha256,
    }


def _queue_environment_response(proposal, *, response_executor=None) -> int:
    from ._shared import _world

    if not proposal.executor:
        raise ValueError("an executor-bound response is required before approval")
    if response_executor is None:
        response_executor = environment_response_registry().get(proposal.executor)
    executor_binding = _environment_response_executor_binding(response_executor)
    return int(_world().create_approval(
        "security.environment_response",
        risk="critical",
        scope=proposal.target,
        detail=_environment_response_approval_detail(
            proposal, executor_binding=executor_binding,
        ),
        provenance="security.env_hunt.response.v1",
        requested_by="system:env_hunt",
    ))


def _environment_response_approval_detail(
    proposal,
    *,
    executor_binding: dict[str, str] | None = None,
) -> str:
    from maverick.approval_cards import encode_operation_approval_detail

    payload = _response_payload(proposal)
    if executor_binding is None:
        executor = environment_response_registry().get(proposal.executor)
        executor_binding = _environment_response_executor_binding(executor)
    return encode_operation_approval_detail(
        action="security.environment_response",
        summary=f"Execute defensive response {proposal.action}",
        target_label=f"{proposal.action}: {proposal.target}"[:500],
        target={
            "proposal_id": proposal.proposal_id,
            "target": proposal.target,
            "executor": proposal.executor,
        },
        parameters=payload,
        parameter_summary=[
            f"Defensive action: {proposal.action}",
            f"Executor: {proposal.executor}",
            f"Executor revision: {executor_binding['revision']}",
            f"Proposal SHA-256: {proposal.digest}",
        ],
        actor="system:env_hunt",
        role="security_response_operator",
        input_versions={"proposal_sha256": proposal.digest},
        credential_versions=executor_binding,
        known_effects=[
            "Invokes the named defensive executor once after all approval gates pass."
        ],
        unresolved_assumptions=[
            "The target still denotes the same external environment resource.",
            "The executor may observe changed external state at execution time.",
        ],
        before="The defensive response proposal is inert.",
        after="The exact reviewed defensive response may execute once.",
        irreversible=True,
        ttl_seconds=24 * 3600,
    )


def _response_proposal_from_record(record: dict):
    from maverick.env_hunt import ResponseProposal

    return ResponseProposal(
        proposal_id=str(record["proposal_id"]),
        action=str(record["action"]),
        target=str(record["target"]),
        reason=str(record["reason"]),
        evidence=_evidence_refs(record.get("evidence", ())),
        parameters=dict(record.get("parameters") or {}),
        executor=str(record.get("executor") or ""),
        audit_accepted=record.get("audit_accepted") is True,
    )


def _auto_environment_response(env_hunt, finding, investigation):
    """Return a conservative, inert playbook for clearly scoped severe events."""
    if finding.severity not in {"high", "critical"}:
        return None
    timeline = tuple(investigation.timeline)
    identity_entry = next((
        item for item in timeline
        if item.principal and (
            {"T1078", "T1098"}.intersection(finding.mitre_techniques)
            or "identity" in item.category.lower()
            or "auth" in item.category.lower()
        )
    ), None)
    if identity_entry is not None:
        action, target = "revoke_session", identity_entry.principal
    else:
        host_entry = next((
            item for item in timeline
            if item.target and (
                item.source.lower().startswith("edr.")
                or item.source.lower() in {
                    "edr",
                    "host.syslog",
                    "syslog",
                    "kubernetes.audit",
                    "kubernetes_audit",
                }
            )
        ), None)
        if host_entry is None:
            return None
        action, target = "isolate_host", host_entry.target
    executors = environment_response_registry().names()
    executor = executors[0] if len(executors) == 1 else ""
    return env_hunt.propose_response(
        action,
        target,
        (
            f"Human-reviewed response playbook for deterministic finding "
            f"{finding.rule_id}: {finding.title}"
        ),
        finding.evidence,
        executor=executor,
    )


def _attach_response_proposal(
    store,
    investigation: dict,
    proposal,
    *,
    actor: str,
    expected_revision: int | None = None,
    response_executor=None,
) -> tuple[dict, int | None]:
    """Persist an inert exact proposal before optionally queueing its approval."""
    from maverick.env_hunt import RevisionConflict

    if proposal.audit_accepted is not True:
        raise RuntimeError("response proposal audit was not accepted")
    expected = int(investigation["revision"])
    if expected_revision is not None:
        if expected != int(expected_revision):
            raise RevisionConflict(
                f"expected revision {expected_revision}, found {expected} for investigation"
            )
        expected = int(expected_revision)
    proposals = dict(investigation.get("response_proposals") or {})
    proposals[proposal.proposal_id] = asdict(proposal)
    proposal_ids = list(dict.fromkeys([
        *(investigation.get("response_proposal_ids") or []),
        proposal.proposal_id,
    ]))
    updated = store.update_investigation(
        str(investigation["investigation_id"]),
        {
            "response_proposal": asdict(proposal),
            "response_proposals": proposals,
            "response_proposal_ids": proposal_ids,
        },
        expected_revision=expected,
        actor=actor,
    )
    approval_id = None
    if proposal.executor:
        approval_id = _queue_environment_response(
            proposal, response_executor=response_executor,
        )
        approvals = dict(updated.get("response_approval_ids") or {})
        approvals[proposal.proposal_id] = approval_id
        try:
            updated = store.update_investigation(
                str(investigation["investigation_id"]),
                {
                    "approval_id": approval_id,
                    "response_approval_ids": approvals,
                },
                expected_revision=int(updated["revision"]),
                actor=actor,
            )
        except RevisionConflict:
            # A concurrent human workflow may have moved the investigation.
            # The approval is still inert and exact-bound; surface no false
            # claim that its ID was attached to the record.
            approval_id = None
    return updated, approval_id


def _ensure_environment_finding(
    env_hunt, store, finding, events, *, actor: str, full_autonomy: bool,
) -> tuple[bool, bool, bool, int | None]:
    from maverick.env_hunt import RevisionConflict

    created_finding = False
    if store.get_finding(finding.finding_id) is None:
        try:
            store.create_finding(finding, actor=actor)
            created_finding = True
        except RevisionConflict:
            pass
    investigation_model = env_hunt.build_investigation(
        (finding,), events, title=f"SOC: {finding.title}",
    )
    enrichment_providers, allowed_enrichment = (
        _configured_environment_enrichment_providers()
    )
    if full_autonomy and enrichment_providers:
        investigation_model = env_hunt.enrich(
            investigation_model,
            enrichment_providers,
            allowed_sources=allowed_enrichment,
        )
    investigation = store.get_investigation(investigation_model.investigation_id)
    created_investigation = False
    if investigation is None:
        try:
            investigation = store.create_investigation(investigation_model, actor=actor)
            created_investigation = True
        except RevisionConflict:
            investigation = store.get_investigation(investigation_model.investigation_id)
    proposal_created = False
    approval_id = None
    if (
        full_autonomy
        and investigation is not None
        and not investigation.get("response_proposal")
    ):
        proposal = _auto_environment_response(env_hunt, finding, investigation_model)
        if proposal is not None:
            try:
                _updated, approval_id = _attach_response_proposal(
                    store, investigation, proposal, actor=actor,
                )
                proposal_created = True
            except RevisionConflict:
                pass
    return created_finding, created_investigation, proposal_created, approval_id


def _environment_pivot_events(
    env_hunt, registry, body, batch, findings, *, full_autonomy: bool,
):
    """Read one bounded related-event window through the same trusted transport."""
    if not full_autonomy or body.events is not None or not findings:
        return batch.events, 0
    if not env_hunt.connector_pivot_enablement().get(body.connector, False):
        return batch.events, 0
    cited_ids = {
        evidence.event_id for finding in findings for evidence in finding.evidence
    }
    cited_events = [event for event in batch.events if event.event_id in cited_ids]
    principals = sorted({event.principal for event in cited_events if event.principal})[:32]
    targets = sorted({event.target for event in cited_events if event.target})[:32]
    if not principals and not targets:
        return batch.events, 0
    filters = dict(body.filters)
    if principals:
        filters["lightwork_related_principals"] = principals
    if targets:
        filters["lightwork_related_targets"] = targets
    pivot_request = env_hunt.QueryRequest(
        start=body.start,
        end=body.end,
        query="lightwork:related-events-v1",
        filters=filters,
        limit=min(body.limit, 1000),
        read_only=True,
    )
    pivot = registry.ingest(body.connector, pivot_request)
    if not pivot.audited:
        raise RuntimeError("environment investigation pivot audit was not accepted")
    merged = {event.event_id: event for event in batch.events}
    merged.update({event.event_id: event for event in pivot.events})
    ordered = tuple(sorted(
        merged.values(), key=lambda item: (item.observed_at, item.event_id),
    ))
    return ordered, len(pivot.events)


def _run_environment_ingest(body: schemas.EnvironmentIngestIn, actor: str) -> dict:
    env_hunt = _environment_module()
    if body.events is not None:
        if not env_hunt.connector_push_enablement().get(body.connector, False):
            raise env_hunt.ConnectorDisabled(
                f"connector {body.connector} web-push ingestion is disabled"
            )
        registry = env_hunt.ConnectorRegistry()
        connector = _connector_for_batch(env_hunt, body.connector, body.events)
        registry.register(connector)
        query_request = env_hunt.QueryRequest(
            start=0.0,
            end=253_402_300_799.0,
            query="api:bounded-read-only-push",
            limit=len(body.events),
            read_only=True,
        )
        ingestion_mode = "push"
    else:
        factory = _configured_environment_connector_factory(env_hunt)
        registry = env_hunt.ConnectorRegistry()
        registry.register(factory.build_connector(body.connector))
        query_request = env_hunt.QueryRequest(
            start=body.start,
            end=body.end,
            query=body.query,
            filters=body.filters,
            limit=body.limit,
            read_only=True,
        )
        ingestion_mode = "registered_transport"
    batch = registry.ingest(body.connector, query_request)
    if not batch.audited:
        raise RuntimeError("environment ingestion audit was not accepted")
    full_autonomy = _environment_shield_posture(batch.events, body.sigma_rules)
    custom_rules = env_hunt.load_sigma_texts(body.sigma_rules)
    rules = (*env_hunt.curated_rules(), *custom_rules)
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("custom Sigma rule ids must not replace curated rule ids")
    report = env_hunt.scan(batch.events, rules=rules)
    if report.audited_findings != len(report.findings):
        raise RuntimeError("environment detection audit was not accepted")
    investigation_events, pivot_events = _environment_pivot_events(
        env_hunt,
        registry,
        body,
        batch,
        report.findings,
        full_autonomy=full_autonomy,
    )
    store = _environment_store()
    findings_created = investigations_created = proposals_created = approvals_queued = 0
    degraded: list[str] = []
    for finding in report.findings:
        try:
            created, investigation, proposal, approval_id = _ensure_environment_finding(
                env_hunt,
                store,
                finding,
                investigation_events,
                actor=actor,
                full_autonomy=full_autonomy,
            )
        except Exception as exc:  # failure-policy: visible_degradation
            degraded.append(f"persist:{finding.finding_id}:{type(exc).__name__}")
            continue
        findings_created += int(created)
        investigations_created += int(investigation)
        proposals_created += int(proposal)
        approvals_queued += int(approval_id is not None)
    return {
        "connector": batch.connector,
        "ingestion_mode": ingestion_mode,
        "events_received": batch.received,
        "events_accepted": len(batch.events),
        "events_discarded": batch.discarded,
        "raw_events_persisted": batch.raw_persisted,
        "ingestion_audited": batch.audited,
        "shield_available": full_autonomy,
        "reduced_autonomy": not full_autonomy,
        "findings_detected": len(report.findings),
        "sigma_findings": report.sigma_findings,
        "correlation_findings": report.correlation_findings,
        "investigation_pivot_events": pivot_events,
        "audited_findings": report.audited_findings,
        "findings_created": findings_created,
        "investigations_created": investigations_created,
        "response_proposals_created": proposals_created,
        "approvals_queued": approvals_queued,
        "degraded_sources": (
            degraded if full_autonomy
            else ["shield:unavailable_reduced_autonomy", *degraded]
        ),
    }


def _environment_summary(*, include_records: bool) -> dict:
    env_hunt = _environment_module()
    from maverick.shield_policy import shield_available

    shield_present = shield_available()
    store = _environment_store()
    connector_factory = _configured_environment_connector_factory(env_hunt)
    enrichment_providers, allowed_enrichment = _configured_environment_enrichment_providers()
    registered_enrichment = {
        str(provider.name).strip().lower() for provider in enrichment_providers
    }
    findings = store.list_findings(limit=10_000)
    investigations = store.list_investigations(limit=10_000)
    technique_counts: dict[str, dict[str, Any]] = {}
    for finding in findings:
        severity = str(finding.get("severity", "unknown"))
        for technique in finding.get("mitre_techniques", ()):
            name = str(technique).strip().upper()
            if not name:
                continue
            row = technique_counts.setdefault(
                name,
                {"technique": name, "count": 0, "severities": {}},
            )
            row["count"] += 1
            severities = row["severities"]
            severities[severity] = severities.get(severity, 0) + 1
    result = {
        "enabled": True,
        "shield_available": shield_present,
        "reduced_autonomy": not shield_present,
        "response_execution": env_hunt.response_execution_enabled(),
        "response_executors": list(environment_response_registry().names()),
        "connectors": connector_factory.statuses(),
        "enrichment_sources": {
            name: {
                "enabled": True,
                "registered": name in registered_enrichment,
                "available": name in registered_enrichment,
            }
            for name in allowed_enrichment
        },
        "open_findings": sum(
            row.get("status") not in {"resolved", "false_positive", "closed"}
            for row in findings
        ),
        "investigation_count": len(investigations),
        "journal_intact": not store.verify_journal(),
        "pending_audit_records": store.pending_audit_count(),
        "raw_events_persisted": False,
        "attack_heatmap": sorted(
            technique_counts.values(),
            key=lambda row: (-row["count"], row["technique"]),
        ),
    }
    if include_records:
        result.update({"findings": findings, "investigations": investigations})
    return result


@router.get("/soc/stats")
async def environment_threat_stats(request: Request) -> dict:
    require_permission(request, "view")
    _environment_module()
    return await run_in_threadpool(_environment_summary, include_records=False)


@router.get("/soc/summary")
async def environment_threat_summary(request: Request) -> dict:
    require_permission(request, "operate")
    _environment_module()
    return await run_in_threadpool(_environment_summary, include_records=True)


@router.post("/soc/ingest")
async def ingest_environment_telemetry(
    request: Request, body: schemas.EnvironmentIngestIn,
) -> dict:
    require_permission(request, "operate")
    _environment_module()
    _bounded_json(
        {"events": body.events or [], "sigma_rules": body.sigma_rules},
        maximum=_MAX_ENVIRONMENT_BATCH_BYTES,
        label="environment telemetry batch",
    )
    try:
        return await run_in_threadpool(
            _run_environment_ingest, body, _actor(request),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/soc/findings/{finding_id}")
async def get_environment_finding(request: Request, finding_id: str) -> dict:
    require_permission(request, "operate")
    _environment_module()
    record = await run_in_threadpool(_environment_store().get_finding, finding_id[:120])
    if record is None:
        raise HTTPException(status_code=404, detail="no such finding")
    return record


@router.patch("/soc/findings/{finding_id}")
async def update_environment_finding(
    request: Request, finding_id: str, body: schemas.HuntRecordUpdateIn,
) -> dict:
    require_permission(request, "operate")
    module = _environment_module()
    changes = dict(body.changes)
    if set(changes) != {"status"} or changes.get("status") not in _PLATFORM_STATUSES:
        raise HTTPException(status_code=422, detail="only a valid finding status may change")
    return await _hunt_call(
        module,
        _environment_store().update_finding,
        finding_id[:120],
        changes,
        expected_revision=body.expected_revision,
        actor=_actor(request),
    )


@router.get("/soc/investigations/{investigation_id}")
async def get_environment_investigation(
    request: Request, investigation_id: str,
) -> dict:
    require_permission(request, "operate")
    _environment_module()
    record = await run_in_threadpool(
        _environment_store().get_investigation, investigation_id[:120],
    )
    if record is None:
        raise HTTPException(status_code=404, detail="no such investigation")
    return record


@router.patch("/soc/investigations/{investigation_id}")
async def update_environment_investigation(
    request: Request,
    investigation_id: str,
    body: schemas.HuntRecordUpdateIn,
) -> dict:
    require_permission(request, "operate")
    module = _environment_module()
    changes = dict(body.changes)
    if not changes or not set(changes).issubset({"status", "assignee", "summary"}):
        raise HTTPException(status_code=422, detail="unsupported investigation change")
    if "status" in changes and changes["status"] not in _INVESTIGATION_STATUSES:
        raise HTTPException(status_code=422, detail="invalid investigation status")
    for key in ("assignee", "summary"):
        if key in changes and len(str(changes[key])) > (200 if key == "assignee" else 8_000):
            raise HTTPException(status_code=422, detail=f"{key} is too long")
    return await _hunt_call(
        module,
        _environment_store().update_investigation,
        investigation_id[:120],
        changes,
        expected_revision=body.expected_revision,
        actor=_actor(request),
    )


@router.post("/soc/responses", status_code=201)
async def propose_environment_response(
    request: Request, body: schemas.EnvironmentResponseIn,
) -> dict:
    require_permission(request, "operate")
    env_hunt = _environment_module()
    store = _environment_store()
    finding_record = await run_in_threadpool(store.get_finding, body.finding_id)
    investigation = await run_in_threadpool(
        store.get_investigation, body.investigation_id,
    )
    if finding_record is None:
        raise HTTPException(status_code=404, detail="no such finding")
    if investigation is None:
        raise HTTPException(status_code=404, detail="no such investigation")
    if int(investigation.get("revision", 0)) != body.expected_revision:
        raise HTTPException(
            status_code=409,
            detail=(
                f"expected revision {body.expected_revision}, found "
                f"{investigation.get('revision')} for investigation"
            ),
        )
    if body.finding_id not in investigation.get("finding_ids", ()):
        raise HTTPException(
            status_code=422,
            detail="finding is not cited by the selected investigation",
        )
    finding = _finding_record(finding_record)
    try:
        response_executor = environment_response_registry().get(body.executor)
    except KeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    proposal = await run_in_threadpool(
        env_hunt.propose_response,
        body.action,
        body.target,
        body.reason,
        finding.evidence,
        parameters=body.parameters,
        executor=body.executor,
    )
    try:
        updated, approval_id = await run_in_threadpool(
            _attach_response_proposal,
            store,
            investigation,
            proposal,
            actor=_actor(request),
            expected_revision=body.expected_revision,
            response_executor=response_executor,
        )
    except env_hunt.RevisionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "proposal": _jsonable(proposal),
        "proposal_sha256": proposal.digest,
        "investigation": updated,
        "approval_queued": approval_id is not None,
        "approval_id": approval_id,
        "approval_request": None,
        "approval_request_template": _jsonable(
            env_hunt.response_approval_request(proposal)
        ),
        "approval_request_note": (
            "sign only after queue approval, binding its exact approval_id and decided_by"
        ),
    }


def _world_approval_matches(
    proposal,
    row,
    approval_id: int,
    *,
    executor_binding: dict[str, str] | None = None,
) -> bool:
    """Treat the queue as workflow state, never as cryptographic authority."""
    if (
        row is None
        or row.status != "approved"
        or not row.decided_by
        or str(row.id) != str(approval_id)
        or row.action != "security.environment_response"
        or row.provenance != "security.env_hunt.response.v1"
        or row.requested_by != "system:env_hunt"
    ):
        return False
    from maverick.approval_cards import (
        ApprovalCardError,
        decode_approval_detail,
        digest,
        require_current_approval_card,
    )

    target = {
        "proposal_id": proposal.proposal_id,
        "target": proposal.target,
        "executor": proposal.executor,
    }
    payload = _response_payload(proposal)
    if executor_binding is None:
        try:
            executor = environment_response_registry().get(proposal.executor)
            executor_binding = _environment_response_executor_binding(executor)
        except (KeyError, TypeError, ValueError):
            return False
    try:
        card = decode_approval_detail(row.detail)
        if card is None:
            return False
        card = require_current_approval_card(card)
        return (
            card["action"] == "security.environment_response"
            and card["target"]["sha256"] == digest(target)
            and card["parameters"]["sha256"] == digest(payload)
            and card["inputs"] == {"proposal_sha256": proposal.digest}
            and card["credentials"] == executor_binding
        )
    except (ApprovalCardError, KeyError, TypeError, ValueError):
        return False


@router.post("/soc/responses/execute")
async def execute_environment_response(
    request: Request, body: schemas.EnvironmentExecuteIn,
) -> dict:
    require_global_permission(request, "admin")
    execution_actor = _actor(request)
    execution_tenant = _environment_tenant_binding()
    env_hunt = _environment_module()
    from maverick.shield_policy import shield_available

    if not shield_available():
        raise HTTPException(
            status_code=403,
            detail=(
                "response execution is unavailable while Shield is absent; "
                "environment hunting is in reduced-autonomy mode"
            ),
        )
    store = _environment_store()
    investigation = await run_in_threadpool(
        store.get_investigation, body.investigation_id,
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="no such investigation")
    if int(investigation.get("revision", 0)) != body.expected_revision:
        raise HTTPException(
            status_code=409,
            detail=(
                f"expected revision {body.expected_revision}, found "
                f"{investigation.get('revision')} for investigation"
            ),
        )
    proposals = dict(investigation.get("response_proposals") or {})
    proposal_record = proposals.get(body.proposal_id)
    if proposal_record is None:
        singular = investigation.get("response_proposal")
        if isinstance(singular, dict) and singular.get("proposal_id") == body.proposal_id:
            proposal_record = singular
    if not isinstance(proposal_record, dict):
        raise HTTPException(status_code=404, detail="no such stored response proposal")
    proposal = _response_proposal_from_record(proposal_record)
    if proposal.executor != body.executor:
        raise HTTPException(
            status_code=403,
            detail="requested executor is not bound to the approved response proposal",
        )
    approval_ids = dict(investigation.get("response_approval_ids") or {})
    attached = approval_ids.get(body.proposal_id, investigation.get("approval_id"))
    if attached is None or int(attached) != body.approval_id:
        raise HTTPException(
            status_code=403,
            detail="approval is not attached to this exact stored proposal",
        )
    from ._shared import _world

    world_approval = await run_in_threadpool(_world().get_approval, body.approval_id)
    if world_approval is None:
        raise HTTPException(status_code=404, detail="no such governed approval")
    from maverick.approval_signing import trusted_approver_keys

    try:
        trusted_keys = await run_in_threadpool(trusted_approver_keys)
    except Exception as exc:
        raise HTTPException(
            status_code=403,
            detail="response approval trust policy is unavailable",
        ) from exc
    if not trusted_keys:
        raise HTTPException(
            status_code=403,
            detail="response execution requires configured Ed25519 approver keys",
        )
    governed = env_hunt.GovernedApproval(
        proposal_id=proposal.proposal_id,
        proposal_sha256=proposal.digest,
        approval_id=str(body.approval_id),
        approved_by=str(world_approval.decided_by or ""),
        signature=body.signature,
        executor=proposal.executor,
    )
    try:
        executor = environment_response_registry().get(body.executor)
        executor_binding = _environment_response_executor_binding(executor)
    except KeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    # This is the last check before execute_response audits and durably claims
    # the effect. The exact object resolved here is passed through, so a
    # same-name registry replacement cannot ride an earlier approval.
    if not _world_approval_matches(
        proposal,
        world_approval,
        body.approval_id,
        executor_binding=executor_binding,
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "governed approval does not match the exact stored response "
                "or current executor binding"
            ),
        )
    # Re-run the authenticated admin gate after every awaited dependency read
    # and immediately before the durable claim/effect boundary. A revoked or
    # substituted session, actor, or tenant cannot inherit the earlier check.
    require_global_permission(request, "admin")
    if (
        _actor(request) != execution_actor
        or _environment_tenant_binding() != execution_tenant
    ):
        raise HTTPException(
            status_code=403,
            detail="environment response execution authority changed",
        )
    try:
        receipt = await run_in_threadpool(
            env_hunt.execute_response,
            proposal,
            governed,
            approval_verifier=env_hunt.Ed25519ApprovalVerifier(trusted_keys),
            executor=executor,
            execution_ledger=store,
            execution_enabled=env_hunt.response_execution_enabled(),
            actor=execution_actor,
        )
    except env_hunt.ResponseNotAuthorized as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except env_hunt.ResponseExecutionPending as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return _jsonable(receipt)
