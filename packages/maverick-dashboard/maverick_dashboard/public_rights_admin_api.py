"""Administration of the public rights-request form and the tracker's
"Send" actions: properties, templates, regimes, and per-request notices,
extensions, acknowledgements and manual verification.

Everything here sits under normal dashboard authentication (``/api/v1``).
Property and template changes need a global administrator; request actions
need ``operate`` like the rest of the DSAR tracker.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(tags=["public-rights-admin"])
_FORM = "/privacy/rights-form"


def _prf():
    from maverick import public_rights_form

    return public_rights_form


def _module_or_403():
    from .feature_gate import feature_off

    prf = _prf()
    if not prf.enabled():
        raise feature_off("privacy_automation.public_rights_form")
    return prf


def _ops_or_403():
    from maverick import privacy_ops

    from .feature_gate import feature_off

    if not privacy_ops.enabled():
        raise feature_off("privacy_ops", "The privacy register")
    return privacy_ops


def _actor(request: Request) -> str:
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


class PropertyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    organisation: str = Field(min_length=1, max_length=200)
    contact_email: str = Field(min_length=3, max_length=200)
    privacy_policy_url: str = Field(default="", max_length=500)
    default_jurisdiction: str = Field(default="", max_length=32)
    jurisdictions: list[str] = Field(default_factory=list, max_length=40)
    request_types: list[str] = Field(default_factory=list, max_length=20)
    allowed_origins: list[str] = Field(default_factory=list, max_length=20)
    enabled: bool = True


class TemplateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=8000)


class SendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1, max_length=32)
    lawful_basis: str = Field(default="", max_length=2000)
    secure_link: str = Field(default="", max_length=500)
    secure_link_expires: str = Field(default="", max_length=32)


class ExtendIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)
    days: int | None = Field(default=None, ge=1, le=90)


class AssignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: ``user:...`` of someone who may work privacy requests, or "" to unassign.
    assignee: str = Field(default="", max_length=200)


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str = Field(min_length=1, max_length=32)
    reference: str = Field(min_length=1, max_length=512)


# --------------------------------------------------------------------------- #
# Properties, regimes, templates
# --------------------------------------------------------------------------- #

@router.get(f"{_FORM}/regimes")
async def rights_form_regimes(request: Request) -> dict[str, Any]:
    """Verified jurisdictions with the rights each grants and its source,
    the request-type labels, and the regimes still awaiting verification."""
    require_permission(request, "view")
    from maverick import rights_deadlines
    from maverick.public_rights_form import RELATIONSHIPS, REQUEST_TYPE_LABELS

    return {
        "verified_at": rights_deadlines.VERIFIED_AT,
        "regimes": [
            {**row, "source": rights_deadlines.REGIMES[row["id"]]["source"],
             "statutory_text": rights_deadlines.REGIMES[row["id"]]["statutory_text"]}
            for row in rights_deadlines.form_choices()
        ],
        "unverified": [
            {"id": key, **value} for key, value in rights_deadlines.UNVERIFIED.items()
        ],
        "request_types": [
            {"id": key, "label": label} for key, label in REQUEST_TYPE_LABELS.items()
        ],
        "relationships": list(RELATIONSHIPS),
        "non_legal_advice": rights_deadlines.NON_LEGAL_ADVICE,
    }


@router.get(f"{_FORM}/properties")
async def list_rights_form_properties(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    prf = _prf()
    rows = await run_in_threadpool(prf.list_properties)
    from .public_rights_api import _public_base_url
    try:
        base = _public_base_url()
    except HTTPException:
        base = ""
    return {
        "enabled": prf.enabled(),
        "properties": [
            {**row, "public_url": f"{base}/rights/{row['slug']}" if base else "",
             "embed_snippet": _embed_snippet(base, str(row["slug"])) if base else ""}
            for row in rows
        ],
    }


def _embed_snippet(base: str, slug: str) -> str:
    return (
        f'<iframe src="{base}/rights/{slug}" title="Privacy request form" '
        'style="width:100%;min-height:52rem;border:0" loading="lazy"></iframe>'
    )


@router.put(f"{_FORM}/properties/{{slug}}")
async def upsert_rights_form_property(request: Request, slug: str, body: PropertyIn) -> dict:
    require_global_permission(request, "admin")
    prf = _module_or_403()
    from .public_rights_api import _public_base_url
    base = _public_base_url()
    try:
        row = await run_in_threadpool(
            prf.upsert_property, slug[:64], body.model_dump(), actor=_actor(request))
    except prf.PublicRightsFormError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {**row, "public_url": f"{base}/rights/{row['slug']}",
            "embed_snippet": _embed_snippet(base, str(row["slug"]))}


@router.delete(f"{_FORM}/properties/{{slug}}")
async def delete_rights_form_property(request: Request, slug: str) -> dict:
    require_global_permission(request, "admin")
    prf = _module_or_403()
    removed = await run_in_threadpool(prf.delete_property, slug[:64], actor=_actor(request))
    if not removed:
        raise HTTPException(status_code=404, detail="no such property")
    return {"deleted": slug[:64]}


@router.get(f"{_FORM}/templates")
async def list_rights_templates(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    from maverick import rights_templates

    rows = await run_in_threadpool(rights_templates.list_templates)
    return {
        "templates": rows,
        "placeholders": rights_templates.PLACEHOLDERS,
        "kinds": [{"id": k, "label": rights_templates.KIND_LABELS[k]} for k in rights_templates.KINDS],
        "families": _family_labels(),
    }


def _family_labels() -> list[dict[str, str]]:
    from maverick import rights_deadlines

    names: dict[str, list[str]] = {}
    for regime in rights_deadlines.REGIMES.values():
        names.setdefault(regime["family"], []).append(regime["name"])
    return [{"id": family, "label": ", ".join(names.get(family, [family]))}
            for family in rights_deadlines.FAMILIES]


@router.get(f"{_FORM}/templates/{{family}}/{{kind}}/history")
async def rights_template_history(request: Request, family: str, kind: str) -> dict:
    require_permission(request, "view")
    from maverick import rights_templates

    try:
        rows = await run_in_threadpool(rights_templates.history, family[:32], kind[:32])
    except rights_templates.RightsTemplateError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"family": family[:32], "kind": kind[:32], "versions": rows}


@router.put(f"{_FORM}/templates/{{family}}/{{kind}}")
async def save_rights_template(request: Request, family: str, kind: str, body: TemplateIn) -> dict:
    require_global_permission(request, "admin")
    _module_or_403()
    from maverick import rights_templates

    try:
        return await run_in_threadpool(
            rights_templates.save_template, family[:32], kind[:32],
            subject=body.subject, body=body.body, actor=_actor(request))
    except rights_templates.RightsTemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(f"{_FORM}/templates/{{family}}/{{kind}}/reset")
async def reset_rights_template(request: Request, family: str, kind: str) -> dict:
    require_global_permission(request, "admin")
    _module_or_403()
    from maverick import rights_templates

    try:
        return await run_in_threadpool(
            rights_templates.reset_template, family[:32], kind[:32], actor=_actor(request))
    except (rights_templates.RightsTemplateError, KeyError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --------------------------------------------------------------------------- #
# Tracker actions
# --------------------------------------------------------------------------- #

@router.post("/privacy/dsar/{request_id}/send")
async def send_dsar_notice(request: Request, request_id: str, body: SendIn) -> dict:
    """Send one templated notice to the requester (acknowledgement,
    identity follow-up, extension, completion with the secure link, or a
    refusal that must state its lawful basis)."""
    require_permission(request, "operate")
    _ops_or_403()
    prf = _prf()
    extra = {k: v for k, v in body.model_dump().items() if k != "kind" and v}
    try:
        return await run_in_threadpool(
            prf.send_notice, request_id[:64], body.kind, actor=_actor(request), extra=extra)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no such request") from exc
    except prf.PublicRightsFormError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/privacy/dsar/{request_id}/extend")
async def extend_dsar(request: Request, request_id: str, body: ExtendIn) -> dict:
    """Record an extension of the response period with its reason; the
    length and the notice timing are checked against the request's regime."""
    require_permission(request, "operate")
    ops = _ops_or_403()
    try:
        record = await run_in_threadpool(
            ops.extend_dsar, request_id[:64], reason=body.reason, days=body.days,
            extended_by=_actor(request))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="no such request")
    return record


@router.post("/privacy/dsar/{request_id}/acknowledge")
async def acknowledge_dsar(request: Request, request_id: str) -> dict:
    require_permission(request, "operate")
    ops = _ops_or_403()
    record = await run_in_threadpool(
        ops.acknowledge_dsar, request_id[:64], acknowledged_by=_actor(request))
    if record is None:
        raise HTTPException(status_code=404, detail="no such request")
    return record


@router.post("/privacy/dsar/{request_id}/assign")
async def assign_dsar(request: Request, request_id: str, body: AssignIn) -> dict:
    """Name who works a request. Only someone who may work privacy requests
    (``operate``) can be named; the previous assignee stays on the record so
    the list's bulk change can be undone."""
    require_permission(request, "operate")
    ops = _ops_or_403()
    from . import people_directory

    if body.assignee and not people_directory.may(body.assignee, "operate"):
        raise HTTPException(
            status_code=422,
            detail="That person can't work privacy requests. Choose someone from the list.",
        )
    try:
        record = await run_in_threadpool(
            ops.assign_dsar, request_id[:64], body.assignee, assigned_by=_actor(request))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="no such request")
    return record


@router.post("/privacy/dsar/{request_id}/verify")
async def verify_dsar(request: Request, request_id: str, body: VerifyIn) -> dict:
    """An operator records a verification they performed another way
    (document check, account login, ...); ``email_challenge`` is reserved
    for the link the platform itself sends."""
    require_permission(request, "operate")
    ops = _ops_or_403()
    if body.method == "email_challenge":
        raise HTTPException(
            status_code=422,
            detail="email confirmation is recorded automatically when the requester "
                   "opens their link; choose the method you performed",
        )
    try:
        record = await run_in_threadpool(
            ops.verify_dsar, request_id[:64], method=body.method,
            reference=body.reference, verified_by=_actor(request))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="no such request")
    return record
