"""Strict tenant-bound adapter for local technology-compliance scoping.

The adapter accepts only closed questionnaire metadata, enumerated or opaque
answers, evidence digests/references, and signing-key references.  It never
accepts framework prose, raw evidence, signing-key values, tenant selectors, or
actor selectors.  All operations remain local and provider neutral.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_REF_PATTERN = r"^ref:[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_EVIDENCE_PATTERN = r"^evidence:[A-Za-z0-9][A-Za-z0-9_.:-]{0,114}$"
_KEY_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
VersionPath = Annotated[int, ApiPath(ge=1, le=1_000_000)]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
OpaqueRef = Annotated[
    str,
    StringConstraints(strict=True, min_length=5, max_length=124, pattern=_REF_PATTERN),
]
EvidenceRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=10,
        max_length=124,
        pattern=_EVIDENCE_PATTERN,
    ),
]
SigningKeyRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=128,
        pattern=_KEY_REF_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
AnswerInteger = Annotated[int, Field(strict=True, ge=0, le=1_000_000_000)]
AnswerList = Annotated[list[OpaqueId], Field(max_length=64)]
AnswerValue = bool | AnswerInteger | OpaqueId | AnswerList
ScopingDomain = Literal[
    "organization",
    "industry",
    "jurisdiction",
    "data",
    "system",
    "vendor",
    "ai",
    "operational",
]
AnswerType = Literal[
    "boolean",
    "single_choice",
    "multi_choice",
    "integer",
    "opaque_ref",
]
ConditionOperator = Literal[
    "equals",
    "not_equals",
    "contains",
    "in",
    "greater_or_equal",
    "less_or_equal",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConditionIn(_StrictModel):
    question_id: OpaqueId
    operator: ConditionOperator
    value: AnswerValue


class QuestionIn(_StrictModel):
    question_id: OpaqueId
    question_ref: OpaqueRef
    domain: ScopingDomain
    answer_type: AnswerType
    options: list[OpaqueId] = Field(max_length=64)
    required: bool
    condition: ConditionIn | None


class RuleIn(_StrictModel):
    rule_id: OpaqueId
    conditions: list[ConditionIn] = Field(max_length=32)
    framework_ref: OpaqueId
    control_refs: list[OpaqueId] = Field(min_length=1, max_length=256)
    overlap_refs: list[OpaqueId] = Field(max_length=256)
    reason_code: OpaqueId


class QuestionnaireVersionIn(_StrictModel):
    questions: list[QuestionIn] = Field(min_length=8, max_length=256)
    rules: list[RuleIn] = Field(min_length=1, max_length=512)
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class AssessmentIn(_StrictModel):
    questionnaire_id: OpaqueId
    questionnaire_version: int = Field(ge=1, le=1_000_000)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ResponseIn(_StrictModel):
    value: AnswerValue
    evidence_sha256: Digest
    evidence_ref: EvidenceRef
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ResponsibilityAssignmentsIn(_StrictModel):
    first_line: OpaqueRef
    second_line: OpaqueRef
    control_owner: OpaqueRef
    evidence_owner: OpaqueRef


class ComputeScopeIn(_StrictModel):
    responsibility_assignments: ResponsibilityAssignmentsIn
    expected_assessment_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ExportScopeIn(_StrictModel):
    signing_key_ref: SigningKeyRef
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ReportIn(_StrictModel):
    idempotency_key: IdempotencyKey


#: Signing key the dashboard's "Create report" button uses, so no person is
#: ever asked for a key reference. The key itself stays in the environment.
DEFAULT_REPORT_SIGNING_KEY_REF = "env:MAVERICK_COMPLIANCE_SCOPE_SIGNING_KEY"


class PurgeIn(_StrictModel):
    cutoff: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


def _enabled() -> bool:
    from maverick import compliance_scoping as scoping

    return scoping.enabled()


def compliance_scoping_enabled_for_page() -> bool:
    """Read only the exact feature gate without opening tenant storage."""

    return _enabled()


def _scoping():
    from maverick import compliance_scoping as scoping

    try:
        scoping.require_enabled()
    except scoping.ComplianceScopingConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return scoping


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using compliance scoping",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for compliance scoping",
    )
    digest = hashlib.sha256(
        (f"lightwork.compliance-scoping.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"cs-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()
                if key != "display_names" or item}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.compliance_scoping import ComplianceScopingStore
    from maverick.paths import data_dir

    return ComplianceScopingStore(
        data_dir(
            "tech_risk_compliance",
            "compliance-scoping.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
    )


class ComplianceScopingDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def authority(request: Request, dependencies: ComplianceScopingDependencies | None = None):
    """Shared native tenant/principal and injected-store boundary."""
    deps = dependencies or ComplianceScopingDependencies()
    scoping = _scoping()
    tenant = _tenant_id()
    principal = _principal(request, tenant)
    factory = getattr(request.app.state, "compliance_scoping_store_factory", None)

    def resolver() -> str:
        return principal

    try:
        store = (
            factory(
                tenant_id=tenant,
                principal_ref=principal,
                principal_resolver=resolver,
                request=request,
            )
            if callable(factory)
            else deps.store_for(tenant, principal)
        )
    except scoping.ComplianceScopingConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (scoping.ComplianceScopingError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="compliance-scoping store is unavailable",
        ) from exc
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="compliance-scoping store is unavailable",
        )
    return scoping, tenant, store


def create_compliance_scoping_router(  # noqa: C901, PLR0915
    dependencies: ComplianceScopingDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ComplianceScopingDependencies()
    router = APIRouter(
        prefix="/compliance/scoping",
        tags=["compliance-scoping"],
    )

    def bound_authority(request: Request):
        return authority(request, deps)

    async def call(scoping, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except scoping.ComplianceScopingNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except scoping.ComplianceScopingPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except scoping.ComplianceScopingConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except scoping.ComplianceScopingValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except scoping.ComplianceScopingConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except scoping.ComplianceScopingIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance-scoping integrity verification failed",
            ) from exc
        except scoping.ComplianceScopingError as exc:
            raise HTTPException(
                status_code=503,
                detail="compliance-scoping operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick.compliance_scoping import ComplianceScopingStore

        return {
            "schema": "lightwork.compliance-scoping-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            **ComplianceScopingStore.product_boundaries(),
            "network_io": False,
            "provider_writes": False,
            "external_discovery_performed": False,
            "certification_performed": False,
            "live_acceptance_verified": False,
            "live_customer_acceptance_verified": False,
            "signing_input_is_reference_only": True,
            "status_request_external_network_io": False,
        }

    @router.get("/records")
    async def records(
        request: Request,
        limit: int = Query(default=200, ge=1, le=1_000),
    ) -> dict[str, Any]:
        """Every questionnaire, assessment, scope and report in this
        workspace, newest first, for the page's record lists."""

        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        listed = await call(scoping, store.list_records, tenant, limit=limit)
        return {
            "questionnaires": [
                {
                    "questionnaire_id": q.questionnaire_id,
                    "version": q.version,
                    "status": q.status,
                    "revision": q.revision,
                    "questions": len(q.questions),
                    "rules": len(q.rules),
                    "created_at": q.created_at,
                    **({"display_names": dict(q.display_names)} if q.display_names else {}),
                }
                for q in listed["questionnaires"]
            ],
            "assessments": [
                {
                    "assessment_id": a.assessment_id,
                    "questionnaire_id": a.questionnaire_id,
                    "questionnaire_version": a.questionnaire_version,
                    "status": a.status,
                    "answered": len(a.answers),
                    "revision": a.revision,
                    "retained_until": a.retained_until,
                    "created_at": a.created_at,
                }
                for a in listed["assessments"]
            ],
            "scopes": [
                {
                    "scope_id": sc.scope_id,
                    "assessment_id": sc.assessment_id,
                    "status": sc.status,
                    "frameworks": list(sc.applicable_frameworks),
                    "controls": len(sc.control_applicability),
                    "overlaps": len(sc.overlaps),
                    "approved": bool(sc.approved_by),
                    "finalized": bool(sc.finalized_by),
                    "revision": sc.revision,
                    "retained_until": sc.retained_until,
                    "created_at": sc.created_at,
                }
                for sc in listed["scopes"]
            ],
            "reports": [
                {
                    "export_id": e.export_id,
                    "scope_id": e.scope_id,
                    "created_at": e.created_at,
                }
                for e in listed["exports"]
            ],
        }

    @router.post("/scopes/{scope_id}/report")
    async def create_report(request: Request, scope_id: ObjectPath, body: ReportIn):
        """Create a signed report for a finalized scope with the deployment's
        signing key (the page never asks for a key reference)."""

        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        scope = await call(scoping, store.get_scope, tenant, scope_id)
        export_id = "report-" + hashlib.sha256(
            f"{scope_id}:{body.idempotency_key}".encode()
        ).hexdigest()[:24]
        return _jsonable(
            await call(
                scoping,
                store.export_scope,
                tenant,
                scope_id,
                export_id,
                signing_key_ref=DEFAULT_REPORT_SIGNING_KEY_REF,
                retained_until=scope.retained_until,
                idempotency_key=body.idempotency_key,
            )
        )

    @router.put("/questionnaires/{questionnaire_id}/versions")
    async def create_questionnaire(
        request: Request,
        questionnaire_id: ObjectPath,
        body: QuestionnaireVersionIn,
    ):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        payload = body.model_dump()
        payload["questions"] = [item.model_dump() for item in body.questions]
        payload["rules"] = [item.model_dump() for item in body.rules]
        return _jsonable(
            await call(
                scoping,
                store.create_questionnaire_version,
                tenant,
                questionnaire_id,
                **payload,
            )
        )

    @router.get("/questionnaires/{questionnaire_id}/versions/{version}")
    async def get_questionnaire(
        request: Request,
        questionnaire_id: ObjectPath,
        version: VersionPath,
    ):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(scoping, store.get_questionnaire, tenant, questionnaire_id, version)
        )

    @router.post("/questionnaires/{questionnaire_id}/versions/{version}/publish")
    async def publish_questionnaire(
        request: Request,
        questionnaire_id: ObjectPath,
        version: VersionPath,
        body: RevisionIn,
    ):
        require_global_permission(request, "admin")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.publish_questionnaire,
                tenant,
                questionnaire_id,
                version,
                **body.model_dump(),
            )
        )

    @router.put("/assessments/{assessment_id}")
    async def create_assessment(
        request: Request,
        assessment_id: ObjectPath,
        body: AssessmentIn,
    ):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.create_assessment,
                tenant,
                assessment_id,
                **body.model_dump(),
            )
        )

    @router.get("/assessments/{assessment_id}")
    async def get_assessment(request: Request, assessment_id: ObjectPath):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(await call(scoping, store.get_assessment, tenant, assessment_id))

    @router.get("/assessments/{assessment_id}/required-questions")
    async def required_questions(
        request: Request,
        assessment_id: ObjectPath,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        items = await call(
            scoping,
            store.next_required_questions,
            tenant,
            assessment_id,
            limit=limit,
        )
        assessment = await call(scoping, store.get_assessment, tenant, assessment_id)
        questionnaire = await call(scoping, store.get_questionnaire, tenant,
                                   assessment.questionnaire_id, assessment.questionnaire_version)
        rendered = _jsonable(items)
        if questionnaire.display_names:
            for question in rendered:
                question["display_name"] = questionnaire.display_names.get(question["question_ref"], "")
                question["option_labels"] = {option: questionnaire.display_names.get(option, option)
                                             for option in question["options"]}
        return {"items": rendered, "count": len(items)}

    @router.post("/assessments/{assessment_id}/responses/{question_id}")
    async def record_response(
        request: Request,
        assessment_id: ObjectPath,
        question_id: ObjectPath,
        body: ResponseIn,
    ):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.record_response,
                tenant,
                assessment_id,
                question_id,
                **body.model_dump(),
            )
        )

    @router.put("/assessments/{assessment_id}/scopes/{scope_id}")
    async def compute_scope(
        request: Request,
        assessment_id: ObjectPath,
        scope_id: ObjectPath,
        body: ComputeScopeIn,
    ):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        payload = body.model_dump()
        payload["responsibility_assignments"] = body.responsibility_assignments.model_dump()
        return _jsonable(
            await call(
                scoping,
                store.compute_scope,
                tenant,
                assessment_id,
                scope_id,
                **payload,
            )
        )

    @router.get("/scopes/{scope_id}")
    async def get_scope(request: Request, scope_id: ObjectPath):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        scope = await call(scoping, store.get_scope, tenant, scope_id)
        result = _jsonable(scope)
        questionnaire = await call(scoping, store.get_questionnaire, tenant,
                                   scope.questionnaire_id, scope.questionnaire_version)
        if questionnaire.display_names:
            result["display_names"] = dict(questionnaire.display_names)
        return result

    async def scope_projection(request: Request, scope_id: str, field: str):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        scope = await call(scoping, store.get_scope, tenant, scope_id)
        return _jsonable(getattr(scope, field))

    @router.get("/scopes/{scope_id}/overlaps")
    async def get_overlaps(request: Request, scope_id: ObjectPath):
        items = await scope_projection(request, scope_id, "overlaps")
        return {"items": items, "count": len(items)}

    @router.get("/scopes/{scope_id}/crosswalks")
    async def get_crosswalks(request: Request, scope_id: ObjectPath):
        items = await scope_projection(request, scope_id, "crosswalks")
        return {"items": items, "count": len(items)}

    @router.get("/scopes/{scope_id}/responsibilities")
    async def get_responsibilities(request: Request, scope_id: ObjectPath):
        return await scope_projection(request, scope_id, "responsibility_assignments")

    @router.post("/scopes/{scope_id}/approve")
    async def approve_scope(request: Request, scope_id: ObjectPath, body: RevisionIn):
        require_global_permission(request, "admin")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.approve_scope,
                tenant,
                scope_id,
                **body.model_dump(),
            )
        )

    @router.post("/scopes/{scope_id}/finalize")
    async def finalize_scope(request: Request, scope_id: ObjectPath, body: RevisionIn):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.finalize_scope,
                tenant,
                scope_id,
                **body.model_dump(),
            )
        )

    @router.put("/scopes/{scope_id}/exports/{export_id}")
    async def export_scope(
        request: Request,
        scope_id: ObjectPath,
        export_id: ObjectPath,
        body: ExportScopeIn,
    ):
        require_permission(request, "operate")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(
            await call(
                scoping,
                store.export_scope,
                tenant,
                scope_id,
                export_id,
                **body.model_dump(),
            )
        )

    @router.get("/exports/{export_id}")
    async def get_export(request: Request, export_id: ObjectPath):
        require_permission(request, "view")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(await call(scoping, store.get_export, tenant, export_id))

    @router.post("/retention/purge")
    async def purge(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        scoping, tenant, store = bound_authority(request)
        return _jsonable(await call(scoping, store.purge_expired, tenant, **body.model_dump()))

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        scoping, tenant, store = bound_authority(request)
        result = _jsonable(await call(scoping, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_compliance_scoping_router()

__all__ = [
    "DEFAULT_REPORT_SIGNING_KEY_REF",
    "ComplianceScopingDependencies",
    "compliance_scoping_enabled_for_page",
    "create_compliance_scoping_router",
    "router",
]
