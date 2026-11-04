"""Authenticated app controls for governed research-candidate promotion.

The browser can inspect lifecycle state and submit human decisions.  Tenant,
principal, current role authority, policy, artifact observations, deployment
adapter, and signing material remain server-owned.  A deployment that has not
installed the trusted promotion composition gets a readable unavailable state
and every mutation fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionInterrupted,
    CandidatePromotionNotFound,
    CandidatePromotionUnavailable,
)
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import (
    caller_principal,
    has_global_permission,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
_PURPOSE_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}$"
_SHA_PATTERN = r"^[a-f0-9]{64}$"
_REQUIRED_METHODS = (
    "proposal_options",
    "list",
    "inspect",
    "request",
    "review",
    "stage",
    "activate",
    "assess_canary",
    "rollback",
    "reconcile",
)


class _PrivatePromotionRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def private_validation(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={
                        "detail": "Candidate promotion request is malformed; reload the current record"
                    },
                    headers={"Cache-Control": "private, no-store"},
                )

        return private_validation


router = APIRouter(
    prefix="/promotions",
    tags=["research-candidate-promotions"],
    route_class=_PrivatePromotionRoute,
)
page_router = APIRouter(tags=["research-candidate-promotions"])
CandidatePath = Annotated[str, Path(min_length=1, max_length=128, pattern=_ID_PATTERN)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Confirmed(_Strict):
    context: str = Field(pattern=_SHA_PATTERN)
    confirm: bool


class _Reviewed(_Confirmed):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class PromotionReview(_Reviewed):
    approve: bool
    reason_code: str = Field(pattern=_PURPOSE_PATTERN, max_length=64)
    note: str = Field(min_length=1, max_length=1024)
    evidence_sha256: str | None = Field(default=None, pattern=_SHA_PATTERN)


class PromotionRollback(_Reviewed):
    reason_code: str = Field(pattern=_PURPOSE_PATTERN, max_length=64)


class CandidateProposal(_Confirmed):
    candidate_id: str = Field(pattern=_ID_PATTERN)
    run_id: str = Field(pattern=_ID_PATTERN)
    target_preset: str = Field(pattern=_ID_PATTERN)


def _service(request: Request, *, required: bool = True):
    state = request.app.state
    value = getattr(state, "candidate_promotions", None)
    factory = getattr(state, "candidate_promotions_factory", None)
    if value is None and callable(factory):
        try:
            value = factory(state)
        except TypeError:
            value = factory()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            value = None
    if value is None or any(not callable(getattr(value, name, None)) for name in _REQUIRED_METHODS):
        if required:
            raise HTTPException(
                503,
                "Candidate promotion is unavailable until an installation administrator configures its trusted study, target preset, artifact, policy, and deployment adapters",
            )
        return None
    return value


def _binding(
    request: Request,
    response: Response,
    payload: _Confirmed | None = None,
    *,
    administrator: bool = False,
) -> tuple[str, str, str]:
    require_permission(request, "operate")
    if administrator:
        require_global_permission(request, "admin")
    actor = caller_principal(request)
    tenant = current_tenant_id_strict()
    if not actor or not actor.startswith("user:") or not tenant:
        raise HTTPException(403, "Sign in with a named account and select a research workspace")
    response.headers["Cache-Control"] = "private, no-store"
    context = context_for(request)
    if payload is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Account or workspace changed; reload candidate promotions")
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm this candidate promotion action")
    return tenant, actor, context


async def _call(function: Callable, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        # A deliberate refusal already carries its own status and message.
        raise
    except CandidatePromotionNotFound as exc:
        raise HTTPException(404, "Candidate promotion was not found in this workspace") from exc
    except CandidatePromotionDenied as exc:
        raise HTTPException(403, str(exc)) from exc
    except (CandidatePromotionConflict, CandidatePromotionInterrupted) as exc:
        raise HTTPException(409, str(exc)) from exc
    except CandidatePromotionUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, "Candidate promotion input is invalid") from exc
    except Exception as exc:  # noqa: BLE001 - do not disclose stores or deployment adapters
        raise HTTPException(
            503,
            "Candidate promotion state is unavailable; inspect the current deployment before retrying",
        ) from exc


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _projection(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the review surface without artifact locations or authority objects."""

    manifest = _mapping(value.get("manifest"))
    study = _mapping(manifest.get("study"))
    run = _mapping(manifest.get("run"))
    target = _mapping(manifest.get("target"))
    resources = _mapping(manifest.get("resources"))
    review = _mapping(value.get("review"))
    block = _mapping(value.get("block"))
    deployment = _mapping(value.get("deployment"))

    def deployment_item(name: str, keys: tuple[str, ...]) -> dict[str, Any] | None:
        item = _mapping(deployment.get(name))
        return None if not item else {key: item.get(key) for key in keys}

    artifacts = []
    for raw in manifest.get("artifacts", ()) if isinstance(manifest, Mapping) else ():
        item = _mapping(raw)
        artifacts.append(
            {
                key: item.get(key)
                for key in ("artifact_id", "kind", "sha256", "size_bytes")
            }
        )
    lineage = []
    for raw in run.get("lineage", ()) if isinstance(run, Mapping) else ():
        item = _mapping(raw)
        lineage.append(
            {
                key: item.get(key)
                for key in (
                    "kind",
                    "asset_id",
                    "version",
                    "manifest_sha256",
                    "required_action_if_revoked",
                )
            }
        )
    events = []
    for raw in value.get("events", ()):
        item = _mapping(raw)
        events.append(
            {
                key: item.get(key)
                for key in (
                    "sequence",
                    "state",
                    "actor",
                    "recorded_at",
                    "details",
                    "event_sha256",
                )
            }
        )
    result = {
        "candidate_id": value.get("candidate_id"),
        "requested_by": value.get("requested_by"),
        "candidate_principal": value.get("candidate_principal"),
        "manifest_sha256": value.get("manifest_sha256"),
        "policy_sha256": value.get("policy_sha256"),
        "state": value.get("state"),
        "revision": value.get("revision"),
        "created_at": value.get("created_at"),
        "updated_at": value.get("updated_at"),
        "study": {
            key: study.get(key)
            for key in (
                "conclusion",
                "report_sha256",
                "conclusion_evidence_sha256",
                "evaluator_id",
                "evaluator_version",
                "metric_protocol_sha256",
            )
        },
        "run": {
            key: run.get(key)
            for key in (
                "run_id",
                "run_manifest_sha256",
                "registry_binding_sha256",
                "result_sha256",
                "output_artifact_sha256",
            )
        },
        "target": {
            key: target.get(key)
            for key in (
                "target_id",
                "expected_active_sha256",
                "state_schema",
                "queued_intent_schema",
                "external_reconciliation_schema",
            )
        },
        "resources": {
            key: resources.get(key)
            for key in (
                "max_memory_bytes",
                "max_storage_bytes",
                "max_cpu_cores",
                "required_providers",
            )
        },
        "artifacts": artifacts,
        "lineage": lineage,
        "review": (
            None
            if not review
            else {
                key: review.get(key)
                for key in (
                    "reviewed_by",
                    "approved",
                    "reason_code",
                    "note",
                    "evidence_sha256",
                    "decision_sha256",
                    "reviewed_at",
                    "expires_at",
                )
            }
        ),
        "block": (
            None
            if not block
            else {
                key: block.get(key) for key in ("reason_code", "detail", "remediation")
            }
        ),
        "deployment": (
            None
            if not deployment
            else {
                "before": deployment_item(
                    "before",
                    (
                        "target_id",
                        "active_artifact_sha256",
                        "state_schema",
                        "queued_intent_schema",
                        "rollback_compatible",
                        "evidence_sha256",
                    ),
                ),
                "stage_receipt": deployment_item(
                    "stage_receipt",
                    ("operation_id", "action", "before_sha256", "after_sha256", "evidence_sha256"),
                ),
                "activation_receipt": deployment_item(
                    "activation_receipt",
                    ("operation_id", "action", "before_sha256", "after_sha256", "evidence_sha256"),
                ),
                "canary": deployment_item(
                    "canary", ("active_artifact_sha256", "metrics", "evidence_sha256", "passed", "failures")
                ),
                "rollback_receipt": deployment_item(
                    "rollback_receipt",
                    ("operation_id", "action", "before_sha256", "after_sha256", "evidence_sha256"),
                ),
                "reconciliation": deployment_item(
                    "reconciliation",
                    (
                        "active_artifact_sha256",
                        "state_schema",
                        "queued_intent_schema",
                        "state_restored",
                        "pending_intents_reconciled",
                        "external_state_reconciled",
                        "evidence_sha256",
                    ),
                ),
            }
        ),
        "events": events,
    }
    if target.get("state_schema") == "lightwork.rule-only-flow-release.v1":
        from .local_flow_promotions import release_status
        try:
            result["local_release"] = release_status(manifest)
        except Exception:
            result["local_release"] = {"kind": "rule_only_workflow", "can_assess": False,
                                      "evidence": "The current workflow release could not be verified. Refresh before deciding."}
        # The native customer journey needs saved names, versions and decisions;
        # exact commitments remain inside the canonical coordinator's record.
        result = {key: result[key] for key in ("candidate_id", "requested_by", "candidate_principal", "state",
                  "revision", "created_at", "updated_at", "local_release")}
        result["review"] = {key: review.get(key) for key in ("reviewed_by", "approved", "reason_code", "note", "reviewed_at")} if review else None
        result["block"] = {"detail": block.get("detail")} if block else None
        result["events"] = [{key: item.get(key) for key in ("sequence", "state", "actor", "recorded_at")} for item in events]
    return result


@router.get("")
async def promotion_overview(
    request: Request,
    response: Response,
    limit: Annotated[int, Query(ge=1, le=256)] = 100,
):
    tenant, actor, context = _binding(request, response)
    service = _service(request, required=False)
    if service is None:
        return {
            "context": context,
            "available": False,
            "can_manage": has_global_permission(request, "admin"),
            "can_propose": False,
            "completed_runs": [],
            "target_presets": [],
            "items": [],
            "detail": "Install trusted study, target preset, artifact, policy, and deployment adapters before proposing candidates.",
        }
    rows = await _call(service.list, tenant, actor, limit=limit)
    try:
        options = await _call(service.proposal_options, tenant, actor)
    except HTTPException as exc:
        if exc.status_code != 503 or not getattr(request.app.state, "local_flow_promotions_installed", False):
            raise
        options = {"completed_runs": [], "target_presets": []}
    run_choices = []
    if getattr(request.app.state, "local_flow_promotions_installed", False) and options["completed_runs"]:
        from .local_flow_promotions import _target_record, store
        record = _target_record()
        name = store.load_flow_snapshot(record["root"]).name
        run_choices = [{"value": run_id, "label": name + " · saved version " + str(record["version"]) + " · successful practice"}
                       for run_id in options["completed_runs"]]
    return {
        "context": context,
        "available": True,
        "can_manage": has_global_permission(request, "admin"),
        "can_propose": True,
        "completed_runs": options["completed_runs"],
        "completed_run_choices": run_choices,
        "target_presets": options["target_presets"],
        "items": [{**_projection(item), "can_decide": actor not in {item.get("requested_by"), item.get("candidate_principal")}} for item in rows],
        "detail": "Every effect rechecks current reviewer, policy, lineage, artifact, and operator authority.",
    }


@router.post("", status_code=201)
async def request_promotion(
    payload: CandidateProposal,
    request: Request,
    response: Response,
):
    """Create a candidate using only server-admitted study and target material."""

    tenant, actor, _ = _binding(request, response, payload)
    value = await _call(
        _service(request).request,
        tenant,
        actor,
        candidate_id=payload.candidate_id,
        run_id=payload.run_id,
        target_preset=payload.target_preset,
    )
    return _projection(value)


@router.get("/{candidate_id}")
async def inspect_promotion(
    candidate_id: CandidatePath,
    request: Request,
    response: Response,
):
    tenant, actor, context = _binding(request, response)
    value = await _call(_service(request).inspect, tenant, actor, candidate_id)
    return {"context": context, "candidate": _projection(value)}


@router.post("/{candidate_id}/review")
async def review_promotion(
    candidate_id: CandidatePath,
    payload: PromotionReview,
    request: Request,
    response: Response,
):
    tenant, actor, _ = _binding(request, response, payload, administrator=True)
    evidence_sha256 = payload.evidence_sha256 or hashlib.sha256(
        json.dumps(
            {
                "schema": "lightwork.candidate-promotion-app-review-evidence.v1",
                "tenant": tenant,
                "candidate_id": candidate_id,
                "reviewer": actor,
                "expected_revision": payload.expected_revision,
                "approve": payload.approve,
                "reason_code": payload.reason_code,
                "note": " ".join(payload.note.split()),
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    value = await _call(
        _service(request).review,
        tenant,
        actor,
        candidate_id,
        expected_revision=payload.expected_revision,
        approve=payload.approve,
        reason_code=payload.reason_code,
        evidence_sha256=evidence_sha256,
        note=payload.note,
    )
    return _projection(value)


async def _transition(
    method: str,
    candidate_id: str,
    payload: _Reviewed,
    request: Request,
    response: Response,
    **kwargs,
):
    tenant, actor, _ = _binding(request, response, payload, administrator=True)
    function = getattr(_service(request), method)
    if method == "assess_canary":
        row = await _call(_service(request).inspect, tenant, actor, candidate_id)
        if row.get("manifest", {}).get("target", {}).get("state_schema") == "lightwork.rule-only-flow-release.v1":
            from .local_flow_promotions import release_status
            report = await _call(release_status, row["manifest"])
            if not report["can_assess"]:
                raise HTTPException(409, "Complete a real run of this exact published release, then refresh before assessing its failure rate.")
    value = await _call(
        function,
        tenant,
        actor,
        candidate_id,
        expected_revision=payload.expected_revision,
        **kwargs,
    )
    return _projection(value)


@router.post("/{candidate_id}/stage")
async def stage_promotion(
    candidate_id: CandidatePath, payload: _Reviewed, request: Request, response: Response
):
    return await _transition("stage", candidate_id, payload, request, response)


@router.post("/{candidate_id}/activate")
async def activate_promotion(
    candidate_id: CandidatePath, payload: _Reviewed, request: Request, response: Response
):
    return await _transition("activate", candidate_id, payload, request, response)


@router.post("/{candidate_id}/canary")
async def assess_promotion_canary(
    candidate_id: CandidatePath, payload: _Reviewed, request: Request, response: Response
):
    return await _transition("assess_canary", candidate_id, payload, request, response)


@router.post("/{candidate_id}/rollback")
async def rollback_promotion(
    candidate_id: CandidatePath,
    payload: PromotionRollback,
    request: Request,
    response: Response,
):
    return await _transition(
        "rollback",
        candidate_id,
        payload,
        request,
        response,
        reason_code=payload.reason_code,
    )


@router.post("/{candidate_id}/reconcile")
async def reconcile_promotion(
    candidate_id: CandidatePath, payload: _Reviewed, request: Request, response: Response
):
    return await _transition("reconcile", candidate_id, payload, request, response)


@page_router.get("/static/lightwork-candidate-promotions.js")
async def candidate_promotion_ui_asset():
    from .app import _STATIC_DIR

    return FileResponse(
        _STATIC_DIR / "lightwork-candidate-promotions.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


__all__ = ["page_router", "router"]
