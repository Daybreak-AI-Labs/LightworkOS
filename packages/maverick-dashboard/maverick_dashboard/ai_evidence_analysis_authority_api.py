"""Admin-only enrollment API for the stock AI Evidence Analysis composition.

These routes accept authority metadata and digests only. They never accept raw
artifact bytes, extracted text, prompts, credentials, tenant selectors, or
caller-selected adapters. Tenant and administrator authority come from the
authenticated dashboard request.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from maverick import ai_evidence_analysis as evidence
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .ai_evidence_analysis_composition import (
    AIEvidenceAnalysisAuthorityConflict,
    AIEvidenceAnalysisCompositionError,
    EvidenceAuthorityRegistry,
    bootstrap_local_adapter_authorities,
    rotate_local_adapter_authority,
)
from .auth import require_global_permission, require_permission

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_MAX_UPLOAD_BYTES = 104_857_600
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_MEDIA_BY_NAME = {
    "jpeg": evidence.MEDIA_JPEG,
    "pdf": evidence.MEDIA_PDF,
    "png": evidence.MEDIA_PNG,
    "text": evidence.MEDIA_TEXT,
    "xlsx": evidence.MEDIA_XLSX,
}

OpaqueRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_REF_PATTERN,
    ),
]
OpaquePath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_REF_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=_DIGEST_PATTERN,
    ),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ArtifactAuthorityIn(_StrictModel):
    case_ref: OpaqueRef
    media_type: Literal["pdf", "jpeg", "png", "xlsx", "text"]
    content_sha256: Digest
    byte_length: int = Field(strict=True, ge=1, le=104_857_600)
    source_ref: OpaqueRef
    source_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    acquired_at: float | int = Field(gt=0, lt=100_000_000_000.0)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    expected_registry_revision: int = Field(default=0, strict=True, ge=0)


class CriterionIn(_StrictModel):
    criterion_id: OpaqueRef
    revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    control_ref: OpaqueRef
    control_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    control_sha256: Digest
    legal_basis_ref: OpaqueRef
    legal_basis_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    legal_basis_sha256: Digest
    stakeholder_requirement_ref: OpaqueRef
    stakeholder_requirement_revision: int = Field(
        strict=True,
        ge=1,
        le=2_147_483_647,
    )
    stakeholder_requirement_sha256: Digest
    expected_fact_code: OpaqueRef
    gap_code: OpaqueRef
    remediation_code: OpaqueRef
    weight_bps: int = Field(strict=True, ge=1, le=10_000)


class CriteriaAuthorityIn(_StrictModel):
    revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    criteria: list[CriterionIn] = Field(min_length=1, max_length=128)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    expected_registry_revision: int = Field(default=0, strict=True, ge=0)


class ReviewerAuthorityIn(_StrictModel):
    revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    capabilities: list[Literal["approve", "reject", "revoke"]] = Field(
        min_length=1,
        max_length=3,
    )
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    expected_registry_revision: int = Field(default=0, strict=True, ge=0)


class RevokeAuthorityIn(_StrictModel):
    expected_registry_revision: int = Field(strict=True, ge=1, le=2_147_483_647)


def _tenant_id() -> str:
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before managing evidence authorities",
        )
    return tenant


def _registry(request: Request) -> EvidenceAuthorityRegistry:
    tenant = _tenant_id()
    factory = getattr(
        request.app.state,
        "ai_evidence_analysis_authority_registry_factory",
        None,
    )
    if not callable(factory):
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis authority registry is unavailable",
        )
    try:
        registry = factory(tenant)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis authority registry is unavailable",
        ) from exc
    if not isinstance(registry, EvidenceAuthorityRegistry) or registry.tenant_id != tenant:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis authority registry is unavailable",
        )
    return registry


async def _call(function, *args: Any, **kwargs: Any):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except AIEvidenceAnalysisAuthorityConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="evidence authority state or revision changed",
        ) from exc
    except AIEvidenceAnalysisCompositionError as exc:
        raise HTTPException(
            status_code=422,
            detail="evidence authority request is invalid",
        ) from exc
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="evidence authority operation failed",
        ) from exc


def _authority_out(authority: object, registry_revision: int) -> dict[str, object]:
    material = asdict(authority)  # type: ignore[arg-type]
    # Criteria references and digests are authority metadata, not extracted
    # artifact content. No raw source material can enter this projection.
    return {
        "schema": "lightwork.ai-evidence.authority-enrollment.v1",
        "registry_revision": registry_revision,
        "authority": material,
        "raw_artifact_content_persisted": False,
        "extracted_text_persisted": False,
        "external_acceptance_verified": False,
    }


def create_ai_evidence_analysis_authority_router() -> APIRouter:
    router = APIRouter(
        prefix="/ai-evidence-analysis/authorities",
        tags=["ai-evidence-analysis-authorities"],
    )

    @router.get("/status")
    async def status(request: Request) -> dict[str, object]:
        require_global_permission(request, "audit")
        report = await _call(_registry(request).verify_integrity)
        return {
            **asdict(report),
            "raw_artifact_content_persisted": False,
            "extracted_text_persisted": False,
            "local_adapter_attestation_scope": "local_reference_self_pinned",
            "external_acceptance_verified": False,
        }

    @router.get("/artifacts")
    async def list_artifacts(request: Request) -> dict[str, object]:
        """Registered documents that can be analyzed now, for the page picker.

        Read-only and bound to the caller's workspace registry; it returns the
        same metadata an analysis record already exposes to viewers.
        """
        require_permission(request, "view")
        items = await _call(_registry(request).list_usable_artifacts)
        return {"items": items, "count": len(items)}

    @router.post("/artifacts/register")
    async def register_uploaded_artifact(
        request: Request,
        name: Annotated[str, Query(min_length=1, max_length=200)],
        matter: Annotated[str, Query(min_length=1, max_length=80)],
        received_at: Annotated[float, Query(gt=0, lt=100_000_000_000.0)],
        valid_days: Annotated[int, Query(ge=30, le=365)] = 90,
    ) -> dict[str, object]:
        """Register an uploaded document; the server computes its fingerprint.

        Same administrator authority as ``PUT /artifacts/{id}``. The raw body
        is read within the media limit, hashed and discarded -- it is never
        stored or returned.
        """
        require_global_permission(request, "admin")
        if valid_days not in (30, 90, 365):
            raise HTTPException(status_code=422, detail="evidence authority request is invalid")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        media_type = next(
            (value for value in _MEDIA_BY_NAME.values() if value == content_type), None
        )
        if media_type is None:
            raise HTTPException(status_code=415, detail="evidence media type is unsupported")
        chunks: list[bytes] = []
        observed = 0
        async for chunk in request.stream():
            observed += len(chunk)
            if observed > _MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="evidence artifact is too large")
            chunks.append(bytes(chunk))
        content = b"".join(chunks)
        chunks.clear()
        try:
            authority, revision = await _call(
                _registry(request).enroll_uploaded_artifact,
                content,
                media_type=media_type,
                display_name=name,
                matter=matter,
                received_at=received_at,
                valid_seconds=valid_days * 86_400,
            )
        finally:
            del content
        return _authority_out(authority, revision)

    @router.get("/criteria")
    async def list_criteria(request: Request) -> dict[str, object]:
        """Review criteria sets that can be used now, for the page picker."""
        require_permission(request, "view")
        items = await _call(_registry(request).list_usable_criteria)
        return {"items": items, "count": len(items)}

    @router.post("/bootstrap")
    async def bootstrap(request: Request) -> dict[str, object]:
        require_global_permission(request, "admin")
        extraction, analysis = await _call(
            bootstrap_local_adapter_authorities,
            _registry(request),
        )
        return {
            "schema": "lightwork.ai-evidence.local-adapter-bootstrap.v1",
            "adapters": [asdict(extraction), asdict(analysis)],
            "attestation_scope": "local_reference_self_pinned",
            "external_acceptance_verified": False,
        }

    @router.put("/artifacts/{artifact_id}")
    async def enroll_artifact(
        request: Request,
        artifact_id: OpaquePath,
        body: ArtifactAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        values = body.model_dump()
        values["media_type"] = _MEDIA_BY_NAME[body.media_type]
        authority, revision = await _call(
            _registry(request).enroll_artifact,
            artifact_id=artifact_id,
            **values,
        )
        return _authority_out(authority, revision)

    @router.post("/artifacts/{artifact_id}/revoke")
    async def revoke_artifact(
        request: Request,
        artifact_id: OpaquePath,
        body: RevokeAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, revision = await _call(
            _registry(request).revoke_artifact,
            artifact_id,
            **body.model_dump(),
        )
        return _authority_out(authority, revision)

    @router.put("/criteria/{criteria_set_id}")
    async def enroll_criteria(
        request: Request,
        criteria_set_id: OpaquePath,
        body: CriteriaAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        values = body.model_dump(exclude={"criteria"})
        criteria = tuple(
            evidence.EvidenceCriterion(
                **item.model_dump(),
                criterion_sha256="0" * 64,
            )
            for item in body.criteria
        )
        authority, revision = await _call(
            _registry(request).enroll_criteria,
            criteria_set_id=criteria_set_id,
            criteria=criteria,
            **values,
        )
        return _authority_out(authority, revision)

    @router.post("/criteria/{criteria_set_id}/revoke")
    async def revoke_criteria(
        request: Request,
        criteria_set_id: OpaquePath,
        body: RevokeAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, revision = await _call(
            _registry(request).revoke_criteria,
            criteria_set_id,
            **body.model_dump(),
        )
        return _authority_out(authority, revision)

    @router.put("/reviewers/{reviewer_ref}")
    async def enroll_reviewer(
        request: Request,
        reviewer_ref: OpaquePath,
        body: ReviewerAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, revision = await _call(
            _registry(request).enroll_reviewer,
            reviewer_ref=reviewer_ref,
            **body.model_dump(),
        )
        return _authority_out(authority, revision)

    @router.post("/reviewers/{reviewer_ref}/revoke")
    async def revoke_reviewer(
        request: Request,
        reviewer_ref: OpaquePath,
        body: RevokeAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, revision = await _call(
            _registry(request).revoke_reviewer,
            reviewer_ref,
            **body.model_dump(),
        )
        return _authority_out(authority, revision)

    @router.post("/adapters/{stage}/{adapter_id}/{revision}/revoke")
    async def revoke_adapter(
        request: Request,
        stage: Literal["analysis", "extraction"],
        adapter_id: OpaquePath,
        revision: int,
        body: RevokeAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, registry_revision = await _call(
            _registry(request).revoke_adapter,
            stage=stage,
            adapter_id=adapter_id,
            revision=revision,
            **body.model_dump(),
        )
        return _authority_out(authority, registry_revision)

    @router.post("/adapters/{stage}/{adapter_id}/{revision}/rotate")
    async def rotate_adapter(
        request: Request,
        stage: Literal["analysis", "extraction"],
        adapter_id: OpaquePath,
        revision: int,
        body: RevokeAuthorityIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        authority, registry_revision = await _call(
            rotate_local_adapter_authority,
            _registry(request),
            stage=stage,
            adapter_id=adapter_id,
            revision=revision,
            **body.model_dump(),
        )
        return _authority_out(authority, registry_revision)

    return router


router = create_ai_evidence_analysis_authority_router()

__all__ = [
    "ArtifactAuthorityIn",
    "CriteriaAuthorityIn",
    "CriterionIn",
    "ReviewerAuthorityIn",
    "RevokeAuthorityIn",
    "create_ai_evidence_analysis_authority_router",
    "router",
]
