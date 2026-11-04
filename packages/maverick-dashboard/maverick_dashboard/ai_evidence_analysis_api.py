"""Strict authenticated API for tenant-bound multimodal evidence analysis.

The upload request body is the artifact itself and is streamed into bounded
memory.  It is not parsed through ``UploadFile``/multipart spooling and is
never written by this module.  One versioned JSON header carries only opaque
artifact/source/criteria selectors and exact revision/digest pins.  Tenant,
actor, retention lifetime, stores, extraction/analysis adapters, adapter
authorities, source authorities, criteria authorities, and reviewer authority
are all resolved by deployment-owned server dependencies.
"""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OPERATION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_METADATA_HEADER = "x-lightwork-evidence-metadata"
_MAX_METADATA_HEADER_CHARACTERS = 4_096
_MEDIA_NAME_BY_TYPE = {
    "image/jpeg": "jpeg",
    "application/pdf": "pdf",
    "image/png": "png",
    "text/plain": "text",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
}
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
AnalysisPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
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
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_OPERATION_PATTERN,
    ),
]
Timestamp = Annotated[
    float | int,
    Field(gt=0, lt=100_000_000_000.0),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AnalyzeUploadMetadata(_StrictModel):
    """The only caller-supplied metadata accepted beside artifact bytes."""

    schema_name: Literal["lightwork.ai-evidence.upload-metadata.v1"] = Field(alias="schema")
    artifact_id: OpaqueId
    source_ref: OpaqueId
    source_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    acquired_at: Timestamp
    expected_artifact_authority_sha256: Digest
    criteria_set_id: OpaqueId
    expected_criteria_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_criteria_authority_sha256: Digest
    idempotency_key: IdempotencyKey


class ReviewIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    decision: Literal["approve", "reject"]
    idempotency_key: IdempotencyKey


class RevokeIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    reason_code: OpaqueId
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=500)


class AiEvidenceAnalysisDependencies:
    """Lazy, server-owned composition seams for deployment and isolated tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str, Request], Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        lifetime_for: Callable[[str, str, Request], tuple[float, float]] | None = None,
        status_settings_for: Callable[[str], Mapping[str, object]] | None = None,
        maintenance_for: Callable[..., Any] | None = None,
    ) -> None:
        for dependency in (
            store_for,
            enabled_probe,
            lifetime_for,
            status_settings_for,
            maintenance_for,
        ):
            if dependency is not None and not callable(dependency):
                raise TypeError("AI evidence-analysis dependency must be callable")
        self.store_for = store_for
        self.enabled_probe = enabled_probe
        self.lifetime_for = lifetime_for
        self.status_settings_for = status_settings_for
        self.maintenance_for = maintenance_for


def _ops():
    from maverick import ai_evidence_analysis as evidence

    return evidence


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using AI evidence analysis",
        )
    return tenant


def _actor_ref(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(request, error_detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.ai-evidence.api-principal.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"ai-evidence-api.{digest[:40]}"


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _selected_callable(request: Request, state_name: str, fallback: object) -> object:
    selected = getattr(request.app.state, state_name, None)
    return selected if callable(selected) else fallback


def _probe_status(
    request: Request,
    dependencies: AiEvidenceAnalysisDependencies,
    tenant_id: str,
) -> tuple[bool, bool]:
    probe = _selected_callable(
        request,
        "ai_evidence_analysis_enabled_probe",
        dependencies.enabled_probe,
    )
    if not callable(probe):
        return False, False
    try:
        enabled = probe(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis configuration is unavailable",
        ) from exc
    if type(enabled) is not bool:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis configuration is unavailable",
        )
    return enabled, True


def _tenant_status_settings(
    request: Request,
    dependencies: AiEvidenceAnalysisDependencies,
    tenant_id: str,
    evidence: Any,
    *,
    enabled: bool,
) -> tuple[dict[str, int], dict[str, object], bool, bool]:
    resolver = _selected_callable(
        request,
        "ai_evidence_analysis_status_settings_resolver",
        dependencies.status_settings_for,
    )
    if not enabled or not callable(resolver):
        return {}, {}, callable(resolver), False
    try:
        result = resolver(tenant_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis media policy is unavailable",
        ) from exc
    expected = {
        "schema",
        "supported_media",
        "enabled_media_names",
        "parser_sandbox_configured",
        "ocr_configured",
        "legacy_xls_configured",
        "authority_history_capacity",
        "authority_retention_seconds",
        "store_opened",
        "runtime_parser_probe_performed",
    }
    if not isinstance(result, Mapping) or set(result) != expected:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis media policy is unavailable",
        )
    raw_media = result.get("supported_media")
    names = result.get("enabled_media_names")
    booleans = (
        result.get("parser_sandbox_configured"),
        result.get("ocr_configured"),
        result.get("legacy_xls_configured"),
        result.get("store_opened"),
        result.get("runtime_parser_probe_performed"),
    )
    if (
        result.get("schema") != "lightwork.ai-evidence.tenant-status-settings.v1"
        or not isinstance(raw_media, Mapping)
        or not isinstance(names, list)
        or not names
        or len(names) != len(set(names))
        or any(not isinstance(name, str) or not name for name in names)
        or any(type(value) is not bool for value in booleans)
        or result.get("store_opened") is not False
        or result.get("runtime_parser_probe_performed") is not False
        or not isinstance(result.get("authority_history_capacity"), int)
        or isinstance(result.get("authority_history_capacity"), bool)
        or not 4 <= int(result["authority_history_capacity"]) <= 1_000_000
        or not isinstance(result.get("authority_retention_seconds"), int)
        or isinstance(result.get("authority_retention_seconds"), bool)
        or not 3_600 <= int(result["authority_retention_seconds"]) <= 315_360_000
    ):
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis media policy is unavailable",
        )
    media: dict[str, int] = {}
    for media_type, maximum in raw_media.items():
        if (
            not isinstance(media_type, str)
            or media_type not in evidence.SUPPORTED_MEDIA_TYPES
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1 <= maximum <= evidence.artifact_byte_limit(media_type)
        ):
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis media policy is unavailable",
            )
        media[media_type] = maximum
    if (
        not media
        or set(names) != {_MEDIA_NAME_BY_TYPE[media_type] for media_type in media}
    ):
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis media policy is unavailable",
        )
    projected = {
        "enabled_media_names": list(names),
        "parser_sandbox_configured": result["parser_sandbox_configured"],
        "ocr_configured": result["ocr_configured"],
        "legacy_xls_configured": result["legacy_xls_configured"],
        "authority_history_capacity": result["authority_history_capacity"],
        "authority_retention_seconds": result["authority_retention_seconds"],
        "store_opened_for_status": False,
        "runtime_parser_probe_performed_for_status": False,
    }
    return dict(sorted(media.items())), projected, True, True


def _metadata(request: Request) -> AnalyzeUploadMetadata:
    values = request.headers.getlist(_METADATA_HEADER)
    if len(values) != 1 or not 1 <= len(values[0]) <= _MAX_METADATA_HEADER_CHARACTERS:
        raise HTTPException(status_code=422, detail="evidence upload metadata is invalid")
    try:
        return AnalyzeUploadMetadata.model_validate_json(values[0])
    except (UnicodeError, ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="evidence upload metadata is invalid") from exc


def _media_type(request: Request, evidence: Any) -> str:
    content_type = request.headers.get("content-type", "")
    if content_type not in evidence.SUPPORTED_MEDIA_TYPES:
        raise HTTPException(status_code=415, detail="evidence media type is unsupported")
    if request.headers.get("content-encoding") not in (None, "", "identity"):
        raise HTTPException(status_code=415, detail="encoded evidence uploads are unsupported")
    return content_type


async def _bounded_content(request: Request, maximum: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdecimal():
            raise HTTPException(status_code=400, detail="evidence content length is invalid")
        declared_size = int(declared)
        if declared_size < 1:
            raise HTTPException(status_code=422, detail="evidence artifact is empty")
        if declared_size > maximum:
            raise HTTPException(status_code=413, detail="evidence artifact exceeds its byte limit")
    chunks: list[bytes] = []
    observed = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        observed += len(chunk)
        if observed > maximum:
            raise HTTPException(status_code=413, detail="evidence artifact exceeds its byte limit")
        chunks.append(bytes(chunk))
    if observed < 1:
        raise HTTPException(status_code=422, detail="evidence artifact is empty")
    if declared is not None and observed != int(declared):
        raise HTTPException(status_code=400, detail="evidence content length is invalid")
    return b"".join(chunks)


def _adapter_out(authority: Any) -> dict[str, object]:
    return {
        "adapter_id": authority.adapter_id,
        "revision": authority.revision,
        "authority_sha256": authority.authority_sha256,
        "deterministic": authority.deterministic,
        "network_access": authority.network_access,
        "untrusted_content_mode": authority.untrusted_content_mode,
        "legal_conclusion_enabled": authority.legal_conclusion_enabled,
    }


def _record_out(record: Any) -> dict[str, object]:  # noqa: C901 - closed projection
    """Project a core record without tenant/actor identities or raw material."""

    artifact = record.artifact
    criteria = record.criteria_authority
    output: dict[str, object] = {
        "schema": "lightwork.ai-evidence.api-record.v1",
        "analysis_id": record.analysis_id,
        "status": record.status,
        "revision": record.revision,
        "artifact": {
            "artifact_id": artifact.artifact_id,
            "media_type": artifact.media_type,
            "content_sha256": artifact.content_sha256,
            "byte_length": artifact.byte_length,
            "source_ref": artifact.source_ref,
            "source_revision": artifact.source_revision,
            "acquired_at": artifact.acquired_at,
            "artifact_authority_sha256": artifact.artifact_authority_sha256,
            "descriptor_sha256": artifact.descriptor_sha256,
        },
        "criteria": {
            "criteria_set_id": criteria.criteria_set_id,
            "revision": criteria.revision,
            "authority_sha256": criteria.authority_sha256,
            "items": [
                {
                    "criterion_id": item.criterion_id,
                    "revision": item.revision,
                    "control_ref": item.control_ref,
                    "control_revision": item.control_revision,
                    "control_sha256": item.control_sha256,
                    "legal_basis_ref": item.legal_basis_ref,
                    "legal_basis_revision": item.legal_basis_revision,
                    "legal_basis_sha256": item.legal_basis_sha256,
                    "stakeholder_requirement_ref": item.stakeholder_requirement_ref,
                    "stakeholder_requirement_revision": (item.stakeholder_requirement_revision),
                    "stakeholder_requirement_sha256": item.stakeholder_requirement_sha256,
                    "expected_fact_code": item.expected_fact_code,
                    "gap_code": item.gap_code,
                    "remediation_code": item.remediation_code,
                    "weight_bps": item.weight_bps,
                    "criterion_sha256": item.criterion_sha256,
                }
                for item in criteria.criteria
            ],
        },
        "adapters": {
            "extraction": _adapter_out(record.extraction_adapter_authority),
            "analysis": _adapter_out(record.analysis_adapter_authority),
        },
        "extracted_facts": [
            {
                "fact_id": item.fact_id,
                "fact_code": item.fact_code,
                "locator_sha256": item.locator_sha256,
                "value_sha256": item.value_sha256,
                "confidence_bps": item.confidence_bps,
                "fact_sha256": item.fact_sha256,
            }
            for item in record.extraction.facts
        ],
        "findings": [
            {
                "criterion_id": item.criterion_id,
                "criterion_sha256": item.criterion_sha256,
                "disposition": item.disposition,
                "fact_ids": list(item.fact_ids),
                "confidence_bps": item.confidence_bps,
                "rationale_code": item.rationale_code,
                "assessment_sha256": item.assessment_sha256,
            }
            for item in record.adapter_analysis.assessments
        ],
        "summary": {
            "total_criteria": record.summary.total_criteria,
            "evidence_supported": record.summary.evidence_supported,
            "evidence_partial": record.summary.evidence_partial,
            "evidence_missing": record.summary.evidence_missing,
            "indeterminate": record.summary.indeterminate,
            "extracted_fact_count": record.summary.extracted_fact_count,
            "summary_sha256": record.summary.summary_sha256,
        },
        "justification": {
            "methodology": record.justification.methodology,
            "score_bps": record.justification.score_bps,
            "maximum_bps": record.justification.maximum_bps,
            "score_sha256": record.justification.score_sha256,
            "components": [
                {
                    "criterion_id": item.criterion_id,
                    "weight_bps": item.weight_bps,
                    "coverage_bps": item.coverage_bps,
                    "confidence_bps": item.confidence_bps,
                    "provenance_bps": item.provenance_bps,
                    "component_score_bps": item.component_score_bps,
                    "component_sha256": item.component_sha256,
                }
                for item in record.justification.components
            ],
        },
        "gaps": [
            {
                "criterion_id": item.criterion_id,
                "disposition": item.disposition,
                "gap_code": item.gap_code,
                "remediation_code": item.remediation_code,
                "suggestion_sha256": item.suggestion_sha256,
            }
            for item in record.gaps
        ],
        "provenance": [
            {
                "sequence": item.sequence,
                "stage": item.stage,
                "input_sha256": item.input_sha256,
                "output_sha256": item.output_sha256,
                "previous_link_sha256": item.previous_link_sha256,
                "link_sha256": item.link_sha256,
            }
            for item in record.provenance
        ],
        "provenance_sha256": record.provenance_sha256,
        "human_review": {
            "required": record.human_review_required,
            "decision": record.review_decision,
            "authority_recorded": record.review_authority is not None,
            "reviewed_at": record.reviewed_at,
        },
        "revocation": {
            "authority_recorded": record.revocation_authority is not None,
            "reason_code": record.revocation_reason_code,
            "revoked_at": record.revoked_at,
        },
        "raw_artifact_content_persisted": False,
        "extracted_text_persisted": False,
        "legal_or_compliance_conclusion": record.legal_or_compliance_conclusion,
        "notice": record.notice,
        "valid_until": record.valid_until,
        "retained_until": record.retained_until,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "previous_integrity_sha256": record.previous_integrity_sha256,
        "integrity_sha256": record.integrity_sha256,
    }
    if (
        output["raw_artifact_content_persisted"] is not False
        or output["extracted_text_persisted"] is not False
        or output["legal_or_compliance_conclusion"] is not False
        or output["human_review"]["required"] is not True  # type: ignore[index]
    ):
        raise ValueError("unsafe evidence-analysis projection")
    return output


def _safe_record(record: Any) -> dict[str, object]:
    try:
        return _record_out(record)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="AI evidence-analysis result contract is unavailable",
        ) from exc


def create_ai_evidence_analysis_router(  # noqa: C901 - route-local trust boundaries
    dependencies: AiEvidenceAnalysisDependencies | None = None,
) -> APIRouter:
    deps = dependencies or AiEvidenceAnalysisDependencies()
    router = APIRouter(prefix="/ai-evidence-analysis", tags=["ai-evidence-analysis"])

    def capability(request: Request, tenant_id: str) -> None:
        enabled, configured = _probe_status(request, deps, tenant_id)
        if not configured:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis configuration is unavailable",
            )
        if not enabled:
            raise HTTPException(status_code=403, detail="ai_evidence_analysis_disabled")

    def authority(request: Request):
        evidence = _ops()
        tenant = _tenant_id()
        capability(request, tenant)
        actor = _actor_ref(request, tenant)
        factory = _selected_callable(
            request,
            "ai_evidence_analysis_store_factory",
            deps.store_for,
        )
        if not callable(factory):
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis authority is unavailable",
            )
        try:
            store = factory(tenant, actor, request)
            bound_tenant = store.tenant_id
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis authority is unavailable",
            ) from exc
        required = (
            "analyze",
            "get",
            "get_released",
            "review",
            "revoke",
            "history",
            "retention_due",
            "purge_expired",
            "verify_integrity",
        )
        if bound_tenant != tenant or any(
            not callable(getattr(store, method, None)) for method in required
        ):
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis authority is unavailable",
            )
        return evidence, tenant, actor, store

    def lifetime(request: Request, tenant_id: str, actor_ref: str) -> tuple[float, float]:
        resolver = _selected_callable(
            request,
            "ai_evidence_analysis_lifetime_resolver",
            deps.lifetime_for,
        )
        if not callable(resolver):
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis retention policy is unavailable",
            )
        try:
            selected = resolver(tenant_id, actor_ref, request)
            if (
                type(selected) is not tuple
                or len(selected) != 2
                or type(selected[0]) not in (float, int)
                or type(selected[1]) not in (float, int)
            ):
                raise TypeError("invalid lifetime contract")
            return float(selected[0]), float(selected[1])
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis retention policy is unavailable",
            ) from exc

    async def call(evidence, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except evidence.EvidenceAnalysisNotFound as exc:
            raise HTTPException(status_code=404, detail="evidence analysis not found") from exc
        except evidence.EvidenceAnalysisPermissionError as exc:
            raise HTTPException(
                status_code=403,
                detail="evidence-analysis action is not authorized",
            ) from exc
        except evidence.EvidenceAnalysisConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="evidence-analysis state or authority pin changed",
            ) from exc
        except evidence.EvidenceAnalysisValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="evidence-analysis request is invalid",
            ) from exc
        except evidence.EvidenceAnalysisIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis integrity verification failed",
            ) from exc
        except evidence.EvidenceAnalysisConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis dependency is unavailable",
            ) from exc
        except evidence.EvidenceAnalysisError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis operation failed",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis dependency is unavailable",
            ) from exc

    @router.get("/status")
    async def status(request: Request, response: Response):
        require_permission(request, "view")
        evidence = _ops()
        tenant = _tenant_id()
        enabled, probe_configured = _probe_status(request, deps, tenant)
        factory = _selected_callable(
            request,
            "ai_evidence_analysis_store_factory",
            deps.store_for,
        )
        lifetime_resolver = _selected_callable(
            request,
            "ai_evidence_analysis_lifetime_resolver",
            deps.lifetime_for,
        )
        _secure(response)
        parser_packages = {
            "pypdf": importlib.util.find_spec("pypdf") is not None,
            "openpyxl": importlib.util.find_spec("openpyxl") is not None,
            "pillow": importlib.util.find_spec("PIL") is not None,
        }
        external_parser_binaries = {
            # The Python wrapper alone cannot perform OCR.  Report the external
            # executable separately so package installation is never presented
            # as usable image OCR.
            "tesseract": shutil.which("tesseract") is not None,
        }
        (
            supported_media,
            tenant_media_policy,
            media_policy_probe_configured,
            media_policy_resolved,
        ) = _tenant_status_settings(
            request,
            deps,
            tenant,
            evidence,
            enabled=enabled,
        )
        configured_for_operation_attempt = bool(
            enabled and callable(factory) and callable(lifetime_resolver)
        )
        readiness_probe = _selected_callable(
            request,
            "ai_evidence_analysis_readiness_probe",
            None,
        )
        composition_ready = False
        if enabled and callable(readiness_probe):
            try:
                readiness_result = readiness_probe(tenant)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="AI evidence-analysis readiness is unavailable",
                ) from exc
            if type(readiness_result) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="AI evidence-analysis readiness is unavailable",
                )
            composition_ready = readiness_result
        ready = bool(composition_ready and media_policy_resolved)
        legacy_xls_configured = bool(
            tenant_media_policy.get("legacy_xls_configured", False)
        )
        ocr_configured = bool(tenant_media_policy.get("ocr_configured", False))
        return {
            "schema": "lightwork.ai-evidence.api-status.v1",
            "enabled": enabled,
            # The installed probe is side-effect free and verifies previously
            # provisioned local authorities/stores without opening new ones.
            "ready": ready,
            "configured_for_operation_attempt": configured_for_operation_attempt,
            "operational_composition_verified": ready,
            "configuration": {
                "enabled_probe_configured": probe_configured,
                "store_factory_configured": callable(factory),
                "lifetime_policy_configured": callable(lifetime_resolver),
                "store_opened_for_status": False,
                "selected_adapter_authorities_resolved_for_status": False,
                "tenant_media_policy_probe_configured": (
                    media_policy_probe_configured
                ),
                "tenant_media_policy_resolved_for_status": media_policy_resolved,
            },
            "supported_media": supported_media,
            "tenant_media_policy": tenant_media_policy,
            "local_parser_packages_detected": parser_packages,
            "external_parser_binaries_detected": external_parser_binaries,
            "boundaries": {
                "upload_transport": "bounded_raw_request_body",
                "multipart_temp_spooling_used": False,
                "raw_artifact_content_persisted": evidence.RAW_ARTIFACT_CONTENT_PERSISTED,
                "extracted_text_persisted": evidence.EXTRACTED_TEXT_PERSISTED,
                "ephemeral_memory_zeroization_guaranteed": False,
                "human_review_required": True,
                "legal_or_compliance_conclusion": evidence.LEGAL_OR_COMPLIANCE_CONCLUSION,
                "supported_media_scope": "tenant_enabled_only",
                "legacy_xls_local_parser_configured": legacy_xls_configured,
                "legacy_xls_local_parser_available": bool(
                    ready and legacy_xls_configured
                ),
                "ocr_local_parser_configured": ocr_configured,
                "ocr_local_parser_available": bool(ready and ocr_configured),
                "local_parser_customer_acceptance_verified": False,
                "adapter_selection_caller_controlled": False,
                "tenant_or_actor_caller_fields_accepted": False,
            },
            "notice": evidence.NON_CONCLUSION_NOTICE,
        }

    @router.post("/analyses", status_code=201)
    async def analyze(request: Request, response: Response):
        require_permission(request, "operate")
        if request.query_params:
            raise HTTPException(status_code=422, detail="evidence upload query is invalid")
        evidence, tenant, actor, store = authority(request)
        valid_until, retained_until = lifetime(request, tenant, actor)
        metadata = _metadata(request)
        media_type = _media_type(request, evidence)
        maximum = evidence.artifact_byte_limit(media_type)
        limit_resolver = _selected_callable(
            request,
            "ai_evidence_analysis_artifact_limit_resolver",
            None,
        )
        if callable(limit_resolver):
            try:
                configured_limit = limit_resolver(tenant, media_type)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="AI evidence-analysis upload policy is unavailable",
                ) from exc
            if (
                isinstance(configured_limit, bool)
                or not isinstance(configured_limit, int)
                or not 1 <= configured_limit <= maximum
            ):
                raise HTTPException(
                    status_code=503,
                    detail="AI evidence-analysis upload policy is unavailable",
                )
            maximum = configured_limit
        content = await _bounded_content(request, maximum)
        artifact = evidence.EvidenceArtifact(
            artifact_id=metadata.artifact_id,
            media_type=media_type,
            content=content,
            source_ref=metadata.source_ref,
            source_revision=metadata.source_revision,
            acquired_at=float(metadata.acquired_at),
        )
        try:
            record = await call(
                evidence,
                store.analyze,
                tenant,
                artifact=artifact,
                expected_artifact_authority_sha256=(metadata.expected_artifact_authority_sha256),
                criteria_set_id=metadata.criteria_set_id,
                expected_criteria_revision=metadata.expected_criteria_revision,
                expected_criteria_authority_sha256=(metadata.expected_criteria_authority_sha256),
                submitter_ref=actor,
                valid_until=valid_until,
                retained_until=retained_until,
                idempotency_key=metadata.idempotency_key,
            )
        finally:
            del artifact
            del content
        _secure(response)
        return _safe_record(record)

    @router.get("/analyses")
    async def list_analyses(
        request: Request,
        response: Response,
        status: Literal["pending_review", "review_approved", "review_rejected", "revoked"]
        | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        """This workspace's analyses (current versions), for the page list."""
        require_permission(request, "view")
        evidence, tenant, _actor, store = authority(request)
        records = await call(evidence, store.list_analyses, tenant, status=status, limit=limit)
        items = [_safe_record(item) for item in records]
        _secure(response)
        return {"items": items, "count": len(items)}

    @router.get("/analyses/{analysis_id}")
    async def get_analysis(request: Request, response: Response, analysis_id: AnalysisPath):
        require_permission(request, "view")
        evidence, tenant, _actor, store = authority(request)
        record = await call(evidence, store.get, tenant, analysis_id)
        _secure(response)
        return _safe_record(record)

    @router.get("/analyses/{analysis_id}/released")
    async def get_released(request: Request, response: Response, analysis_id: AnalysisPath):
        require_permission(request, "view")
        evidence, tenant, _actor, store = authority(request)
        record = await call(evidence, store.get_released, tenant, analysis_id)
        _secure(response)
        return _safe_record(record)

    @router.get("/analyses/{analysis_id}/history")
    async def history(request: Request, response: Response, analysis_id: AnalysisPath):
        require_permission(request, "audit")
        evidence, tenant, _actor, store = authority(request)
        records = await call(evidence, store.history, tenant, analysis_id)
        try:
            items = [_record_out(item) for item in records]
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis result contract is unavailable",
            ) from exc
        _secure(response)
        return {"items": items, "count": len(items)}

    @router.post("/analyses/{analysis_id}/review")
    async def review(
        request: Request,
        response: Response,
        analysis_id: AnalysisPath,
        body: ReviewIn,
    ):
        require_permission(request, "operate")
        evidence, tenant, actor, store = authority(request)
        record = await call(
            evidence,
            store.review,
            tenant,
            analysis_id,
            reviewer_ref=actor,
            **body.model_dump(),
        )
        _secure(response)
        return _safe_record(record)

    @router.post("/analyses/{analysis_id}/revoke")
    async def revoke(
        request: Request,
        response: Response,
        analysis_id: AnalysisPath,
        body: RevokeIn,
    ):
        require_permission(request, "admin")
        evidence, tenant, actor, store = authority(request)
        record = await call(
            evidence,
            store.revoke,
            tenant,
            analysis_id,
            reviewer_ref=actor,
            **body.model_dump(),
        )
        _secure(response)
        return _safe_record(record)

    @router.get("/integrity")
    async def integrity(request: Request, response: Response):
        require_permission(request, "audit")
        evidence, tenant, _actor, store = authority(request)
        report = await call(evidence, store.verify_integrity, tenant)
        try:
            payload = {
                "schema": report.schema,
                "analyses": report.analyses,
                "history_records": report.history_records,
                "operations": report.operations,
                "terminal_sha256": report.terminal_sha256,
                "verification_sha256": report.verification_sha256,
            }
        except AttributeError as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis result contract is unavailable",
            ) from exc
        _secure(response)
        return payload

    @router.get("/retention/due")
    async def retention_due(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "audit")
        evidence, tenant, _actor, store = authority(request)
        identifiers = await call(evidence, store.retention_due, tenant, limit=limit)
        items = list(identifiers)
        _secure(response)
        return {"analysis_ids": items, "count": len(items), "as_of": "server_clock"}

    @router.post("/retention/purge")
    async def purge(request: Request, response: Response, body: PurgeIn):
        require_permission(request, "admin")
        evidence, tenant, _actor, store = authority(request)
        maintenance = _selected_callable(
            request,
            "ai_evidence_analysis_maintenance_runner",
            deps.maintenance_for,
        )
        if callable(maintenance):
            result = await call(evidence, maintenance, tenant, limit=body.limit)
            try:
                payload = {
                    "schema": result.schema,
                    "analysis_ids": list(result.purged_analysis_ids),
                    "analyses": result.purged_analyses,
                    "history_records": result.purged_history_records,
                    "operations": result.purged_operations,
                    "analyses_before": result.analyses_before,
                    "analyses_after": result.analyses_after,
                    "authority_registry_records_before": (
                        result.registry_records_before
                    ),
                    "authority_registry_records_after": result.registry_records,
                    "live_authorities": result.live_authorities,
                    "retained_expired_authorities": (
                        result.retained_expired_authorities
                    ),
                    "authority_tombstones": result.authority_tombstones,
                    "compacted_authorities": result.compacted_authorities,
                    "compacted_authority_records": (
                        result.compacted_authority_records
                    ),
                    "purged_authority_tombstones": (
                        result.purged_authority_tombstones
                    ),
                    "authority_compaction_anchor_sha256": (
                        result.authority_compaction_anchor_sha256
                    ),
                    "integrity_verified": result.integrity_verified,
                    "as_of": "server_clock",
                }
            except (AttributeError, TypeError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="AI evidence-analysis result contract is unavailable",
                ) from exc
            _secure(response)
            return payload
        result = await call(evidence, store.purge_expired, tenant, limit=body.limit)
        try:
            payload = {
                "analysis_ids": list(result.analysis_ids),
                "analyses": len(result.analysis_ids),
                "history_records": result.history_records,
                "operations": result.operations,
                "as_of": "server_clock",
            }
        except (AttributeError, TypeError) as exc:
            raise HTTPException(
                status_code=503,
                detail="AI evidence-analysis result contract is unavailable",
            ) from exc
        _secure(response)
        return payload

    return router


router = create_ai_evidence_analysis_router()

__all__ = [
    "AiEvidenceAnalysisDependencies",
    "AnalyzeUploadMetadata",
    "create_ai_evidence_analysis_router",
    "router",
]
