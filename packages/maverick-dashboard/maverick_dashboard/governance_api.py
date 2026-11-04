"""The governance workspace API: FRIA, Annex IV, AI literacy, GRC sync.

Mounted below ``/api/v1/security`` so the legal / privacy / compliance
workspace page can drive the governed registers without the CLI. Every
register mutation records the caller's identity. Authority filings remain human
assertions; only the explicitly confirmed, administrator-only GRC dispatcher
can deliver records to a configured external system.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from . import governance_schemas as schemas
from .auth import require_global_permission, require_permission
from .model_risk_api import _actor, _call, _human_principal, _module, _record_call

router = APIRouter(prefix="/governance", tags=["governance"])


# --------------------------------------------------------------------------
# FRIA (Art. 27)
# --------------------------------------------------------------------------
def _projected_fria(record: dict[str, Any]) -> dict[str, Any]:
    """A view-floor projection: assertion state without the answer bodies.

    Answer text is a tier above viewer summaries (same posture as the
    privacy workspace); it stays behind the operate-floor record fetch
    and draft render.
    """

    elements = record.get("elements") or {}
    return {
        **record,
        "elements": {
            key: (
                None
                if not isinstance(value, dict)
                else {
                    "asserted": True,
                    "citation": value.get("citation"),
                    "asserted_by": value.get("asserted_by"),
                    "asserted_at": value.get("asserted_at"),
                }
            )
            for key, value in elements.items()
        },
    }


@router.get("/fria")
async def list_fria_records(
    request: Request,
    status: str | None = Query(default=None, min_length=1, max_length=32),
) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_frias, status=status)
    return {
        "records": [_projected_fria(row) for row in rows],
        "count": len(rows),
        "elements": conformity.FRIA_ELEMENTS,
    }


@router.get("/fria/{record_id}")
async def get_fria_record(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")

    def _find(wanted: str) -> dict[str, Any] | None:
        for row in conformity.list_frias():
            if row.get("id") == wanted:
                return row
        return None

    record = await _record_call(_find, record_id)
    return {"record": record}


@router.post("/fria", status_code=201)
async def open_fria_record(
    request: Request,
    body: schemas.FRIAOpenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.open_fria,
        body.asset_id,
        context=body.context,
        actor=_actor(request),
    )


@router.post("/fria/{record_id}/elements")
async def assert_fria_element(
    request: Request,
    record_id: str,
    body: schemas.FRIAElementIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.assert_fria_element,
        record_id,
        body.element,
        content=body.content,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/fria/{record_id}/complete")
async def complete_fria_record(
    request: Request,
    record_id: str,
    body: schemas.FRIACompleteIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.complete_fria,
        record_id,
        assessor=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/fria/{record_id}/outdate")
async def outdate_fria_record(
    request: Request,
    record_id: str,
    body: schemas.FRIAOutdateIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.mark_fria_outdated,
        record_id,
        reason=body.reason,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/fria/{record_id}/notification")
async def record_fria_notification(
    request: Request,
    record_id: str,
    body: schemas.FRIANotificationIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_fria_notification,
        record_id,
        authority=body.authority,
        submitted_by=_actor(request),
        submitted_at=body.submitted_at,
        reference=body.reference,
        expected_revision=body.expected_revision,
    )


@router.get("/fria/{record_id}/draft")
async def fria_draft(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    draft = await _call(conformity.render_fria, record_id)
    return {"record_id": record_id, "draft": draft}


# --------------------------------------------------------------------------
# Annex IV checklist (Art. 11(1))
# --------------------------------------------------------------------------
@router.post("/annex-iv", status_code=201)
async def open_annex_iv_record(
    request: Request,
    body: schemas.AnnexIVOpenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    record = await _call(conformity.open_annex_iv, body.asset_id, actor=_actor(request))
    status = await _call(conformity.annex_iv_status, record["id"])
    return {"record": record, "status": status, "items": conformity.ANNEX_IV_ITEMS}


@router.get("/annex-iv/{record_id}")
async def annex_iv_record_status(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    status = await _record_call(conformity.annex_iv_status, record_id)
    return {"status": status, "items": conformity.ANNEX_IV_ITEMS}


@router.post("/annex-iv/{record_id}/items")
async def assert_annex_iv_item(
    request: Request,
    record_id: str,
    body: schemas.AnnexIVItemIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    await _call(
        conformity.assert_annex_iv_item,
        record_id,
        body.item,
        reference=body.reference,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _call(conformity.annex_iv_status, record_id)


@router.get("/annex-iv/{record_id}/render")
async def annex_iv_render(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    rendered = await _call(conformity.render_annex_iv, record_id)
    return {"record_id": record_id, "rendered": rendered}


# --------------------------------------------------------------------------
# Art. 43 conformity-assessment routes
# --------------------------------------------------------------------------
@router.get("/routes")
async def list_assessment_routes(
    request: Request,
    status: str | None = Query(default=None, min_length=1, max_length=32),
) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_assessment_routes, status=status)
    return {"records": rows, "count": len(rows), "routes": conformity.ROUTES}


@router.get("/routes/{asset_id}")
async def get_assessment_route(request: Request, asset_id: str) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    record = await _record_call(conformity.get_assessment_route, asset_id)
    return {"record": record}


@router.post("/routes", status_code=201)
async def record_assessment_route(
    request: Request,
    body: schemas.RouteRecordIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_assessment_route,
        body.asset_id,
        route=body.route,
        annex_iii_point=body.annex_iii_point,
        harmonised_standards_applied=body.harmonised_standards_applied,
        common_specifications_applied=body.common_specifications_applied,
        rationale=body.rationale,
        actor=_actor(request),
    )


@router.post("/routes/{asset_id}/modification")
async def mark_substantial_modification(
    request: Request,
    asset_id: str,
    body: schemas.RouteModificationIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.mark_substantial_modification,
        asset_id,
        reason=body.reason,
        actor=_actor(request),
        expected_revision=body.expected_revision,
        predetermined=body.predetermined,
    )


# --------------------------------------------------------------------------
# AI literacy (Art. 4)
# --------------------------------------------------------------------------
async def _literacy_read(fn: Any) -> Any:
    try:
        return await _call(fn)
    except HTTPException as exc:
        if exc.status_code not in {404, 409, 422, 503}:
            raise
        raise HTTPException(
            503,
            "Training status is unknown because Lightwork could not check the complete record. "
            "This view supports up to 500 roles, 2,000 people and 2,000 training completions. "
            "No complete evidence report was produced.",
        ) from exc


async def _with_literacy_plane(
    literacy: Any,
    payload: dict[str, Any],
    *,
    read_only: bool = False,
) -> dict[str, Any]:
    read = _literacy_read if read_only else _call
    status = await read(literacy.literacy_plane_status)
    return {
        **payload,
        "data_plane": "role_compatibility",
        "authoritative_for_compliance": False,
        "canonical_counts": (status.get("canonical") or {}).get("summary") or {},
        "canonical_available": (status.get("canonical") or {}).get("available")
        is True,
        "reconciliation_required": bool(status.get("reconciliation_required")),
        "reconciliation_notice": status.get("notice"),
    }


@router.get("/literacy/gaps")
async def literacy_gaps(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    literacy = _module("ai_literacy", "ai_literacy")
    gaps = await _literacy_read(literacy.literacy_gaps)
    result = await _with_literacy_plane(literacy, gaps, read_only=True)
    require_permission(request, "view")
    return result


@router.get("/literacy/requirements")
async def literacy_requirements(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    literacy = _module("ai_literacy", "ai_literacy")
    rows = await _literacy_read(literacy.list_requirements)
    result = await _with_literacy_plane(
        literacy,
        {"requirements": rows, "count": len(rows)},
        read_only=True,
    )
    require_permission(request, "view")
    return result


@router.post("/literacy/requirements")
async def set_literacy_requirement(
    request: Request,
    body: schemas.LiteracyRequirementIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    literacy = _module("ai_literacy", "ai_literacy")
    record = await _call(
        literacy.set_role_requirement,
        body.role,
        [row.model_dump() for row in body.trainings],
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _with_literacy_plane(literacy, record)


@router.post("/literacy/assignments")
async def assign_literacy_roles(
    request: Request,
    body: schemas.LiteracyAssignmentIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    literacy = _module("ai_literacy", "ai_literacy")
    record = await _call(
        literacy.assign_roles,
        body.person,
        body.roles,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _with_literacy_plane(literacy, record)


@router.post("/literacy/completions")
async def record_literacy_completion(
    request: Request,
    body: schemas.LiteracyCompletionIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    literacy = _module("ai_literacy", "ai_literacy")
    record = await _call(
        literacy.record_completion,
        body.person,
        body.training,
        completed_at=body.completed_at,
        evidence_ref=body.evidence_ref,
        actor=_actor(request),
    )
    return await _with_literacy_plane(literacy, record)


@router.get("/literacy/evidence")
async def literacy_evidence(request: Request) -> dict[str, Any]:
    require_permission(request, "operate")
    literacy = _module("ai_literacy", "ai_literacy")
    exported = await _literacy_read(literacy.export_evidence)
    result = await _with_literacy_plane(literacy, {"evidence": exported}, read_only=True)
    require_permission(request, "operate")
    return result


# --------------------------------------------------------------------------
# GPAI provider obligations (Art. 53 / Art. 55)
# --------------------------------------------------------------------------
@router.get("/gpai")
async def list_gpai_registers(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_gpai_registers)
    return {
        "records": rows,
        "count": len(rows),
        "obligations": conformity.GPAI_OBLIGATIONS,
        "systemic_obligations": conformity.GPAI_SYSTEMIC_OBLIGATIONS,
    }


@router.post("/gpai", status_code=201)
async def open_gpai_register(
    request: Request,
    body: schemas.GPAIOpenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    record = await _call(
        conformity.open_gpai,
        body.asset_id,
        systemic_risk=body.systemic_risk,
        open_source_exempt=body.open_source_exempt,
        actor=_actor(request),
    )
    status = await _call(conformity.gpai_status, record["id"])
    return {"record": record, "status": status}


@router.get("/gpai/{record_id}")
async def gpai_register_status(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    status = await _record_call(conformity.gpai_status, record_id)
    return {"status": status}


@router.post("/gpai/{record_id}/obligations")
async def assert_gpai_obligation(
    request: Request,
    record_id: str,
    body: schemas.GPAIObligationIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    await _call(
        conformity.assert_gpai_obligation,
        record_id,
        body.obligation,
        reference=body.reference,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _call(conformity.gpai_status, record_id)


# --------------------------------------------------------------------------
# Art. 26 deployer obligations
# --------------------------------------------------------------------------
@router.get("/deployer")
async def list_deployer_registers(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_deployer_registers)
    return {
        "records": rows,
        "count": len(rows),
        "obligations": conformity.DEPLOYER_OBLIGATIONS,
        "conditional_obligations": {
            key: value[:2]
            for key, value in conformity.DEPLOYER_CONDITIONAL_OBLIGATIONS.items()
        },
    }


@router.post("/deployer", status_code=201)
async def open_deployer_register(
    request: Request,
    body: schemas.DeployerOpenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    record = await _call(
        conformity.open_deployer_register,
        body.asset_id,
        workplace_use=body.workplace_use,
        public_authority=body.public_authority,
        controls_input_data=body.controls_input_data,
        requires_dpia=body.requires_dpia,
        actor=_actor(request),
    )
    status = await _call(conformity.deployer_status, record["id"])
    return {"record": record, "status": status}


@router.get("/deployer/{record_id}")
async def deployer_register_status(
    request: Request, record_id: str,
) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    status = await _record_call(conformity.deployer_status, record_id)
    return {"status": status}


@router.post("/deployer/{record_id}/obligations")
async def assert_deployer_obligation(
    request: Request,
    record_id: str,
    body: schemas.DeployerObligationIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    await _call(
        conformity.assert_deployer_obligation,
        record_id,
        body.obligation,
        reference=body.reference,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _call(conformity.deployer_status, record_id)


@router.post("/deployer/{record_id}/oversight")
async def assign_deployer_oversight(
    request: Request,
    record_id: str,
    body: schemas.DeployerOversightIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    await _call(
        conformity.assign_deployer_oversight,
        record_id,
        persons=body.persons,
        reference=body.reference,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _call(conformity.deployer_status, record_id)


# --------------------------------------------------------------------------
# Independent FRIA review (four-eyes)
# --------------------------------------------------------------------------
@router.post("/fria/{record_id}/review")
async def record_fria_review(
    request: Request,
    record_id: str,
    body: schemas.FRIAReviewIn,
) -> dict[str, Any]:
    require_permission(request, "operate", api_scope="approvals:decide")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_fria_review,
        record_id,
        outcome=body.outcome,
        reviewer=_actor(request),
        expected_revision=body.expected_revision,
        notes=body.notes,
    )


# --------------------------------------------------------------------------
# Art. 72 post-market monitoring plans
# --------------------------------------------------------------------------
@router.get("/pmm")
async def list_pmm_plans(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_pmm_plans)
    return {"records": rows, "count": len(rows)}


@router.post("/pmm", status_code=201)
async def record_pmm_plan(
    request: Request,
    body: schemas.PMMPlanIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_pmm_plan,
        body.asset_id,
        plan_reference=body.plan_reference,
        actor=_actor(request),
    )


@router.post("/pmm/{asset_id}/review")
async def record_pmm_review(
    request: Request,
    asset_id: str,
    body: schemas.PMMReviewIn,
) -> dict[str, Any]:
    require_permission(request, "operate", api_scope="approvals:decide")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_pmm_review,
        asset_id,
        outcome=body.outcome,
        actor=_actor(request),
        expected_revision=body.expected_revision,
        plan_reference=body.plan_reference,
    )


# --------------------------------------------------------------------------
# Art. 49 registrations
# --------------------------------------------------------------------------
@router.get("/registrations")
async def list_registrations(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    rows = await _call(conformity.list_registrations)
    return {"records": rows, "count": len(rows), "bases": conformity.REGISTRATION_BASES}


@router.post("/registrations", status_code=201)
async def record_registration(
    request: Request,
    body: schemas.RegistrationIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    return await _call(
        conformity.record_registration,
        body.asset_id,
        basis=body.basis,
        registry=body.registry,
        reference=body.reference,
        actor=_actor(request),
    )


# --------------------------------------------------------------------------
# Art. 13(3) instructions-for-use checklist
# --------------------------------------------------------------------------
@router.post("/ifu", status_code=201)
async def open_ifu_record(
    request: Request,
    body: schemas.IFUOpenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    record = await _call(conformity.open_ifu, body.asset_id, actor=_actor(request))
    status = await _call(conformity.ifu_status, record["id"])
    return {"record": record, "status": status, "items": conformity.IFU_ITEMS}


@router.get("/ifu/{record_id}")
async def ifu_record_status(request: Request, record_id: str) -> dict[str, Any]:
    require_permission(request, "view")
    conformity = _module("eu_conformity", "eu_conformity")
    status = await _record_call(conformity.ifu_status, record_id)
    return {"status": status, "items": conformity.IFU_ITEMS}


@router.post("/ifu/{record_id}/items")
async def assert_ifu_item(
    request: Request,
    record_id: str,
    body: schemas.AnnexIVItemIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    await _call(
        conformity.assert_ifu_item,
        record_id,
        body.item,
        reference=body.reference,
        actor=_actor(request),
        expected_revision=body.expected_revision,
    )
    return await _call(conformity.ifu_status, record_id)


# --------------------------------------------------------------------------
# The per-asset audit bundle: every governance record in one download
# --------------------------------------------------------------------------
@router.get("/bundle/{asset_id}")
async def governance_bundle(request: Request, asset_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    conformity = _module("eu_conformity", "eu_conformity")
    sections: dict[str, Any] = {}

    frias = [
        row
        for row in await _call(conformity.list_frias)
        if row.get("asset_id") == asset_id
    ]
    for row in frias:
        row["draft"] = await _call(conformity.render_fria, row["id"])
    sections["fria"] = frias

    annex = await _call(conformity.get_annex_iv, asset_id)
    if annex is not None:
        sections["annex_iv"] = {
            "status": await _call(conformity.annex_iv_status, annex["id"]),
            "rendered": await _call(conformity.render_annex_iv, annex["id"]),
        }
    sections["assessment_route"] = await _call(
        conformity.get_assessment_route, asset_id
    )
    sections["pmm_plan"] = await _call(conformity.get_pmm_plan, asset_id)
    sections["registration"] = await _call(conformity.get_registration, asset_id)
    ifu = await _call(conformity.get_ifu, asset_id)
    if ifu is not None:
        ifu["status"] = await _call(conformity.ifu_status, ifu["id"])
    sections["instructions_for_use"] = ifu

    try:
        incidents_module = _module("ai_incident_reporting", "ai_incident_reporting")
    except HTTPException:
        sections["serious_incidents"] = {"enabled": False}
    else:
        declarations = [
            row
            for row in await _call(incidents_module.list_declarations)
            if row.get("asset_id") == asset_id
        ]
        for row in declarations:
            row["report_draft"] = await _call(
                incidents_module.render_report, row["id"]
            )
        sections["serious_incidents"] = {
            "enabled": True,
            "declarations": declarations,
        }

    return {
        "asset_id": asset_id,
        "generated_at": time.time(),
        "generated_by": _actor(request),
        "regulation": dict(conformity.REGULATION_METADATA),
        "notice": conformity.NON_CERTIFICATION_NOTICE,
        "sections": sections,
    }


# --------------------------------------------------------------------------
# The needs-attention digest
# --------------------------------------------------------------------------
@router.get("/alerts")
async def needs_attention_digest(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    from maverick import governance_alerts

    return await _call(governance_alerts.digest)


# --------------------------------------------------------------------------
# GRC sync visibility and explicit dispatch
# --------------------------------------------------------------------------
@router.get("/grc-sync/status")
async def grc_sync_status(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    sync = _module("grc_sync", "grc_sync")
    return await _call(sync.sync_status)


@router.get("/grc-sync/outbound")
async def grc_sync_outbound(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_permission(request, "view")
    sync = _module("grc_sync", "grc_sync")
    rows = await _call(sync.list_outbound, limit=limit)
    return {"outbound": rows, "count": len(rows)}


@router.post("/grc-sync/run")
async def run_grc_sync(request: Request, body: schemas.GRCSyncRunIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    human = _human_principal(request)
    sync = _module("grc_sync", "grc_sync")
    return await _call(sync.run_sync, actor=human, limit=body.limit)


@router.post("/grc-sync/outbound/{record_id}/inspect")
async def inspect_grc_delivery(request: Request, record_id: str, body: schemas.GRCInspectIn):
    require_global_permission(request, "admin")
    human = _human_principal(request)
    sync = _module("grc_sync", "grc_sync")
    return await _call(sync.inspect_delivery, record_id, actor=human, **body.model_dump())


@router.post("/grc-sync/outbound/{record_id}/resolve")
async def resolve_grc_delivery(request: Request, record_id: str, body: schemas.GRCResolveIn):
    require_global_permission(request, "admin")
    human = _human_principal(request)
    sync = _module("grc_sync", "grc_sync")
    return await _call(sync.resolve_delivery, record_id, actor=human, **body.model_dump())
