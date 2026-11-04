"""Strict authenticated API for evidence-assisted assessment proposals."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

OpaqueId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    ),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    ),
]
QuestionId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=60,
        pattern=r"^[a-z0-9][a-z0-9_]{0,59}$",
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateProposalIn(_StrictModel):
    assessment_id: OpaqueId
    analysis_ids: list[OpaqueId] = Field(min_length=1, max_length=32)
    idempotency_key: IdempotencyKey


class ReviewProposalIn(_StrictModel):
    decision: Literal["approve", "reject"]
    selected_question_ids: list[QuestionId] = Field(default_factory=list, max_length=500)
    rationale: str = Field(strict=True, min_length=1, max_length=4_000)
    expected_revision: int = Field(strict=True, ge=1, le=2**63 - 1)
    idempotency_key: IdempotencyKey


class ApplyProposalIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2**63 - 1)
    expected_assessment_revision: int = Field(strict=True, ge=1, le=2**63 - 1)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=500)


class AssessmentEvidenceDependencies:
    """Narrow lazy seams for production composition and isolated tests."""

    def __init__(
        self,
        *,
        service_for: Callable[[str, str, Request], Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str, Request], Mapping[str, Any]] | None = None,
    ) -> None:
        for dependency in (service_for, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("assessment evidence dependency must be callable")
        self.service_for = service_for
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using assessment evidence proposals",
        )
    return tenant


def _actor_ref(request: Request, tenant_id: str) -> str:
    try:
        from .assessment_evidence_autopopulation_composition import expected_actor_ref

        return expected_actor_ref(request, tenant_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="an authenticated principal is required",
        ) from exc


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(item)
            for key, item in value.items()
            if key != "_audit_pending"
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_assessment_evidence_autopopulation_router(  # noqa: C901
    dependencies: AssessmentEvidenceDependencies | None = None,
) -> APIRouter:
    deps = dependencies or AssessmentEvidenceDependencies()
    router = APIRouter(
        prefix="/assessment-evidence-autopopulation",
        tags=["assessment-evidence-autopopulation"],
    )

    def enabled(request: Request, tenant: str) -> bool:
        selected = getattr(
            request.app.state,
            "assessment_evidence_autopopulation_enabled_probe",
            None,
        )
        probe = selected if callable(selected) else deps.enabled_probe
        if not callable(probe):
            return False
        try:
            result = probe(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="assessment evidence configuration is unavailable",
            ) from exc
        if type(result) is not bool:
            raise HTTPException(
                status_code=503,
                detail="assessment evidence configuration is unavailable",
            )
        return result

    def service(request: Request) -> tuple[Any, str]:
        tenant = _tenant_id()
        if not enabled(request, tenant):
            raise HTTPException(
                status_code=403,
                detail="assessment_evidence_autopopulation_disabled",
            )
        actor = _actor_ref(request, tenant)
        selected = getattr(
            request.app.state,
            "assessment_evidence_autopopulation_service_factory",
            None,
        )
        factory = selected if callable(selected) else deps.service_for
        if not callable(factory):
            raise HTTPException(
                status_code=503,
                detail="assessment evidence authority is unavailable",
            )
        try:
            value = factory(tenant, actor, request)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="assessment evidence authority is unavailable",
            ) from exc
        required = (
            "create_proposal",
            "get_proposal",
            "list_proposals",
            "review_proposal",
            "apply_proposal",
            "purge_expired",
            "verify_integrity",
            "status",
        )
        if any(not callable(getattr(value, name, None)) for name in required):
            raise HTTPException(
                status_code=503,
                detail="assessment evidence authority is unavailable",
            )
        return value, actor

    def translate(exc: Exception) -> HTTPException:
        from maverick import assessment_evidence_autopopulation as autopop

        if isinstance(exc, autopop.AssessmentEvidenceNotFound):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(
            exc,
            (
                autopop.AssessmentEvidenceConflict,
                autopop.AssessmentEvidenceTransitionError,
            ),
        ):
            return HTTPException(status_code=409, detail=str(exc))
        if isinstance(exc, autopop.AssessmentEvidenceValidationError):
            return HTTPException(status_code=422, detail=str(exc))
        if isinstance(
            exc,
            (
                autopop.AssessmentEvidenceConfigError,
                autopop.AssessmentEvidenceIntegrityError,
            ),
        ):
            return HTTPException(status_code=503, detail=str(exc))
        return HTTPException(status_code=503, detail="assessment evidence operation failed")

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        tenant = _tenant_id()
        if not enabled(request, tenant):
            return {
                "schema": "lightwork.assessment-evidence-status.v1",
                "enabled": False,
                "configured": False,
                "ready": False,
            }
        selected = getattr(
            request.app.state,
            "assessment_evidence_autopopulation_readiness_probe",
            None,
        )
        probe = selected if callable(selected) else deps.readiness_probe
        if callable(probe):
            try:
                result = probe(tenant, request)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="assessment evidence readiness is unavailable",
                ) from exc
            if not isinstance(result, Mapping):
                raise HTTPException(
                    status_code=503,
                    detail="assessment evidence readiness is unavailable",
                )
            return _jsonable(result)
        capability, _actor = service(request)
        try:
            return _jsonable(await run_in_threadpool(capability.status))
        except Exception as exc:
            raise translate(exc) from exc

    @router.post("/proposals", status_code=201)
    async def create_proposal(
        request: Request,
        body: CreateProposalIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        capability, actor = service(request)
        try:
            record = await run_in_threadpool(
                capability.create_proposal,
                body.assessment_id,
                body.analysis_ids,
                actor=actor,
                idempotency_key=body.idempotency_key,
            )
        except Exception as exc:
            raise translate(exc) from exc
        return _jsonable(record)

    @router.get("/proposals")
    async def list_proposals(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        require_permission(request, "audit")
        capability, _actor = service(request)
        try:
            rows = await run_in_threadpool(capability.list_proposals, limit=limit)
        except Exception as exc:
            raise translate(exc) from exc
        items = [
            {
                "id": row["id"],
                "assessment": row["assessment"],
                "status": row["status"],
                "revision": row["revision"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "retained_until": row["retained_until"],
                "proposal_sha256": row["proposal_sha256"],
                "candidate_count": len(row["candidates"]),
                "eligible_candidate_count": sum(
                    1
                    for item in row["candidates"]
                    if item.get("eligible_for_apply") is True
                ),
            }
            for row in rows
        ]
        return {"items": items, "count": len(items), "limit": limit}

    @router.get("/proposals/{proposal_id}")
    async def get_proposal(request: Request, proposal_id: OpaqueId) -> dict[str, Any]:
        require_permission(request, "operate")
        capability, _actor = service(request)
        try:
            record = await run_in_threadpool(capability.get_proposal, proposal_id)
        except Exception as exc:
            raise translate(exc) from exc
        return _jsonable(record)

    @router.post("/proposals/{proposal_id}/review")
    async def review_proposal(
        request: Request,
        proposal_id: OpaqueId,
        body: ReviewProposalIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        capability, actor = service(request)
        try:
            record = await run_in_threadpool(
                capability.review_proposal,
                proposal_id,
                decision=body.decision,
                selected_question_ids=body.selected_question_ids,
                rationale=body.rationale,
                actor=actor,
                expected_revision=body.expected_revision,
                idempotency_key=body.idempotency_key,
            )
        except Exception as exc:
            raise translate(exc) from exc
        return _jsonable(record)

    @router.post("/proposals/{proposal_id}/apply")
    async def apply_proposal(
        request: Request,
        proposal_id: OpaqueId,
        body: ApplyProposalIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        capability, actor = service(request)
        try:
            record = await run_in_threadpool(
                capability.apply_proposal,
                proposal_id,
                actor=actor,
                expected_revision=body.expected_revision,
                expected_assessment_revision=body.expected_assessment_revision,
                idempotency_key=body.idempotency_key,
            )
        except Exception as exc:
            raise translate(exc) from exc
        return _jsonable(record)

    @router.post("/maintenance/purge")
    async def purge_expired(request: Request, body: PurgeIn) -> dict[str, Any]:
        require_permission(request, "admin")
        capability, actor = service(request)
        try:
            purged = await run_in_threadpool(
                capability.purge_expired,
                actor=actor,
                limit=body.limit,
            )
        except Exception as exc:
            raise translate(exc) from exc
        return {"purged_ids": list(purged), "purged": len(purged)}

    @router.get("/integrity")
    async def integrity(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        capability, _actor = service(request)
        try:
            report = await run_in_threadpool(capability.verify_integrity)
        except Exception as exc:
            raise translate(exc) from exc
        return _jsonable(report)

    return router


router = create_assessment_evidence_autopopulation_router()


__all__ = [
    "ApplyProposalIn",
    "AssessmentEvidenceDependencies",
    "CreateProposalIn",
    "PurgeIn",
    "ReviewProposalIn",
    "create_assessment_evidence_autopopulation_router",
    "router",
]
