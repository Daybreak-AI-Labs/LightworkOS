"""Strict tenant-bound HTTP adapter for third-party lifecycle governance.

This adapter exposes only the local provider-neutral control plane.  It never
accepts tenant or actor selectors, performs network I/O, writes to providers,
or treats a governed callback intent as delivered.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import caller_principal, require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
JsonScalar = bool | int | str
JsonRuleValue = JsonScalar | None | list[JsonScalar | None]
Severity = Literal["informational", "low", "medium", "high", "critical"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConditionIn(_StrictModel):
    question_id: OpaqueId
    operator: Literal[
        "equals",
        "not_equals",
        "contains",
        "in",
        "greater_or_equal",
        "less_or_equal",
    ]
    value: JsonRuleValue


class RiskRuleIn(_StrictModel):
    operator: Literal[
        "equals",
        "not_equals",
        "contains",
        "in",
        "greater_or_equal",
        "less_or_equal",
    ]
    value: JsonRuleValue
    severity: Severity
    reason_code: OpaqueId


class QuestionIn(_StrictModel):
    question_id: OpaqueId
    domain: Literal["security", "privacy", "ethics", "compliance", "operational", "ai"]
    prompt_ref: OpaqueId
    response_type: Literal["boolean", "single_choice", "multi_choice", "integer", "text_ref"]
    required: bool
    options: list[OpaqueId] = Field(default_factory=list, max_length=1_000)
    condition: ConditionIn | None = None
    risk_rules: list[RiskRuleIn] = Field(default_factory=list, max_length=1_000)


class MitigationRuleIn(_StrictModel):
    reason_code: OpaqueId
    recommendation_code: OpaqueId
    task_code: OpaqueId
    minimum_severity: Severity


class TemplateCreateIn(_StrictModel):
    title_ref: OpaqueId
    questions: list[QuestionIn] = Field(min_length=1, max_length=1_000)
    mitigation_rules: list[MitigationRuleIn] = Field(default_factory=list, max_length=1_000)
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class ApprovalIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class AssessmentCreateIn(_StrictModel):
    vendor_ref: OpaqueId
    template_id: OpaqueId
    template_version: int = Field(ge=1, le=1_000_000)
    owner_ref: OpaqueId
    respondent_assignments: dict[OpaqueId, OpaqueId] = Field(min_length=1, max_length=1_000)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    idempotency_key: IdempotencyKey


class ResponseIn(_StrictModel):
    value: JsonScalar | list[OpaqueId]
    evidence_sha256: Digest
    evidence_refs: list[OpaqueId] = Field(min_length=1, max_length=1_000)
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class AssessmentTaskIn(RevisionIn):
    status: Literal["open", "completed", "waived"]
    reason_code: OpaqueId
    assignee_ref: OpaqueId
    evidence_sha256: Digest | None = None
    evidence_ref: OpaqueId | None = None
    due_at: float | int = Field(gt=0, lt=100_000_000_000.0)


class DependencyIn(_StrictModel):
    dependency_id: OpaqueId
    kind: Literal["system", "access", "data", "contract"]
    reference: OpaqueId
    evidence_sha256: Digest


class LifecycleCreateIn(_StrictModel):
    vendor_ref: OpaqueId
    owner_ref: OpaqueId
    dependencies: list[DependencyIn] = Field(max_length=1_000)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    idempotency_key: IdempotencyKey


class LifecycleTransitionIn(RevisionIn):
    assessment_id: OpaqueId | None = None
    assessment_revision: int | None = Field(default=None, ge=1)
    target_stage: Literal["active", "suspended"]
    reason_code: OpaqueId


class OffboardingTaskDefinitionIn(_StrictModel):
    task_id: OpaqueId
    dependency_id: OpaqueId
    action: Literal[
        "revoke_access",
        "deprovision_account",
        "terminate_integration",
        "archive_data",
        "notify_owner",
    ]
    assignee_ref: OpaqueId
    callback_required: bool


class BeginOffboardingIn(_StrictModel):
    tasks: list[OffboardingTaskDefinitionIn] = Field(max_length=1_000)
    legal_hold: bool
    legal_hold_evidence_ref: OpaqueId | None = None
    maximum_callback_attempts: int = Field(ge=1, le=20)
    expected_lifecycle_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class LegalHoldIn(RevisionIn):
    active: bool
    evidence_ref: OpaqueId


class OffboardingTaskIn(RevisionIn):
    status: Literal["open", "completed", "blocked"]
    evidence_sha256: Digest | None = None
    attestation_ref: OpaqueId | None = None


class IndependentCompletionIn(_StrictModel):
    completion_attestation_ref: OpaqueId
    expected_plan_revision: int = Field(ge=1, le=1_000_000)
    expected_lifecycle_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ClaimCallbacksIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: int = Field(default=60, ge=1, le=3_600)


class FailCallbackIn(RevisionIn):
    lease_token: OpaqueId
    error_code: OpaqueId
    retry_after_seconds: int = Field(gt=0, le=604_800)


class AckCallbackIn(RevisionIn):
    lease_token: OpaqueId
    delivery_evidence_sha256: Digest


class RequeueCallbackIn(RevisionIn):
    reason_code: OpaqueId


class ExportIn(_StrictModel):
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    before: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


def _enabled() -> bool:
    from maverick import third_party_lifecycle as ops

    return ops.enabled()


def third_party_lifecycle_enabled_for_page() -> bool:
    """Read only the exact config gate; do not open the lifecycle database."""

    return _enabled()


def _ops():
    from maverick import third_party_lifecycle as ops

    try:
        ops.require_enabled()
    except ops.ThirdPartyLifecycleConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using third-party lifecycle",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for third-party lifecycle",
    )
    return _principal_ref_for(tenant_id, subject)


def _principal_ref_for(tenant_id: str, subject: str) -> str:
    """The lifecycle reference for one person (same digest as ``_principal``)."""

    digest = hashlib.sha256(
        (f"lightwork.third-party-lifecycle.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"tpl-principal-{digest[:32]}"


def _unattributed_author(tenant_id: str, principal_ref: str) -> bool:
    """Old local and shared-token records cannot establish two real people."""
    return principal_ref in {
        _principal_ref_for(tenant_id, "authorized-local-operator"),
        _principal_ref_for(tenant_id, "static-dashboard-operator"),
    }


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.paths import data_dir
    from maverick.third_party_lifecycle import ThirdPartyLifecycleStore

    return ThirdPartyLifecycleStore(
        data_dir(
            "third_party_management",
            "third-party-lifecycle.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
    )


class ThirdPartyLifecycleDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def create_third_party_lifecycle_router(  # noqa: C901, PLR0915
    dependencies: ThirdPartyLifecycleDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyLifecycleDependencies()
    router = APIRouter(
        prefix="/third-party/lifecycle",
        tags=["third-party-lifecycle"],
    )

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(request.app.state, "third_party_lifecycle_store_factory", None)

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
        except ops.ThirdPartyLifecycleConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ops.ThirdPartyLifecycleError, OSError) as exc:
            raise HTTPException(
                status_code=503, detail="third-party lifecycle store is unavailable"
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503, detail="third-party lifecycle store is unavailable"
            )
        return ops, tenant, principal, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.ThirdPartyLifecycleNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.ThirdPartyLifecyclePermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.ThirdPartyLifecycleConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.ThirdPartyLifecycleValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.ThirdPartyLifecycleConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.ThirdPartyLifecycleIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party lifecycle integrity verification failed",
            ) from exc
        except ops.ThirdPartyLifecycleError as exc:
            raise HTTPException(
                status_code=503, detail="third-party lifecycle operation failed"
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        return {
            "schema": "lightwork.third-party-lifecycle-status.v1",
            "enabled": _enabled(),
            "principal_ref": _principal(request, tenant),
            "provider_neutral_local_control_plane": True,
            "network_operations_implemented": False,
            "provider_writes_implemented": False,
            "live_provider_acceptance_verified": False,
            "live_customer_acceptance_verified": False,
            "callback_transport_worker_implemented": False,
            "callbacks_are_governed_intent_only": True,
            "status_request_external_network_io": False,
            "raw_provider_credentials_accepted": False,
            "raw_vendor_profile_values_accepted": False,
        }

    # ---- read-only lists for the page (records load on open) -------------

    @router.get("/people")
    async def people(request: Request) -> dict[str, Any]:
        """Workspace members with their lifecycle references, so owners and
        assignees are chosen from a list and shown by name."""
        require_permission(request, "operate")
        tenant = _tenant_id()
        me = _principal(request, tenant)
        from .ui_choices_api import people_choices

        try:
            rows = await run_in_threadpool(people_choices)
        except Exception:
            rows = []
        items = [{"value": _principal_ref_for(tenant, row["value"]), "label": row["label"]}
                 for row in rows]
        if not any(item["value"] == me for item in items):
            items.insert(0, {"value": me, "label": "Me"})
        from .local_owner import available as local_owner_setup_available

        return {
            "me": me,
            "items": items,
            "named_signin": bool((caller_principal(request) or "").startswith("user:")),
            "local_owner_setup_available": local_owner_setup_available(request),
        }

    @router.get("/templates")
    async def list_templates(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        items = _jsonable(await call(ops, store.list_templates, tenant, limit=500))
        for item in items:
            item["needs_named_author"] = _unattributed_author(tenant, item["authored_by"])
        return {"items": items}

    @router.get("/assessments")
    async def list_assessments(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return {"items": _jsonable(await call(ops, store.list_assessments, tenant, limit=500))}

    @router.get("/lifecycles")
    async def list_lifecycles(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return {"items": _jsonable(await call(ops, store.list_lifecycles, tenant, limit=500))}

    @router.get("/offboarding")
    async def list_offboarding(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        items = _jsonable(await call(ops, store.list_offboarding_plans, tenant, limit=500))
        for item in items:
            item["needs_named_initiator"] = _unattributed_author(tenant, item["initiated_by"])
        return {"items": items}

    @router.put("/templates/{template_id}")
    async def create_template(request: Request, template_id: ObjectPath, body: TemplateCreateIn):
        require_permission(request, "operate")
        if not (caller_principal(request) or "").startswith("user:"):
            raise HTTPException(403, "Set up individual sign-ins before writing a questionnaire for approval.")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.create_template_version, tenant, template_id, **body.model_dump())
        )

    @router.get("/templates/{template_id}/versions/{version}")
    async def get_template(request: Request, template_id: ObjectPath, version: int):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.get_template_version, tenant, template_id, version))

    @router.post("/templates/{template_id}/versions/{version}/approve")
    async def approve_template(
        request: Request, template_id: ObjectPath, version: int, body: ApprovalIn
    ):
        require_global_permission(request, "admin")
        if not (caller_principal(request) or "").startswith("user:"):
            raise HTTPException(403, "Sign in with an individual account to approve a questionnaire.")
        ops, tenant, _principal_ref, store = authority(request)
        record = await call(ops, store.get_template_version, tenant, template_id, version)
        if _unattributed_author(tenant, record.authored_by):
            raise HTTPException(
                409,
                "This questionnaire was written before individual sign-ins. Write a new version while signed in, then ask another administrator to approve it.",
            )
        return _jsonable(
            await call(
                ops,
                store.approve_template_version,
                tenant,
                template_id,
                version,
                **body.model_dump(),
            )
        )

    @router.put("/assessments/{assessment_id}")
    async def create_assessment(
        request: Request, assessment_id: ObjectPath, body: AssessmentCreateIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        from .vendor_profile import effect_guard, registered_vendor
        registered_vendor(tenant, body.vendor_ref)
        return _jsonable(
            await call(ops, store.create_assessment, tenant, assessment_id, **body.model_dump(),
                effect_guard=effect_guard(request, tenant, _principal_ref, family="lifecycle"))
        )

    @router.get("/assessments/{assessment_id}")
    async def get_assessment(request: Request, assessment_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.get_assessment, tenant, assessment_id))

    @router.get("/assessments/{assessment_id}/required-questions")
    async def required_questions(request: Request, assessment_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        items = await call(ops, store.required_questions, tenant, assessment_id)
        return {"assessment_id": assessment_id, "required_questions": _jsonable(items)}

    @router.put("/assessments/{assessment_id}/responses/{question_id}")
    async def record_response(
        request: Request, assessment_id: ObjectPath, question_id: ObjectPath, body: ResponseIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.record_response, tenant, assessment_id, question_id, **body.model_dump()
            )
        )

    @router.post("/assessments/{assessment_id}/evaluate")
    async def evaluate_assessment(request: Request, assessment_id: ObjectPath, body: RevisionIn):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.evaluate_assessment, tenant, assessment_id, **body.model_dump())
        )

    @router.put("/assessments/{assessment_id}/tasks/{task_id}")
    async def set_assessment_task(
        request: Request, assessment_id: ObjectPath, task_id: ObjectPath, body: AssessmentTaskIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.set_assessment_task, tenant, assessment_id, task_id, **body.model_dump()
            )
        )

    @router.put("/lifecycles/{lifecycle_id}")
    async def create_lifecycle(request: Request, lifecycle_id: ObjectPath, body: LifecycleCreateIn):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        from .vendor_profile import effect_guard, registered_vendor
        registered_vendor(tenant, body.vendor_ref)
        return _jsonable(
            await call(ops, store.create_lifecycle, tenant, lifecycle_id, **body.model_dump(),
                effect_guard=effect_guard(request, tenant, _principal_ref, family="lifecycle"))
        )

    @router.get("/lifecycles/{lifecycle_id}")
    async def get_lifecycle(request: Request, lifecycle_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.get_lifecycle, tenant, lifecycle_id))

    @router.post("/lifecycles/{lifecycle_id}/transition")
    async def transition_lifecycle(
        request: Request, lifecycle_id: ObjectPath, body: LifecycleTransitionIn
    ):
        if body.target_stage == "suspended":
            require_global_permission(request, "admin")
        else:
            require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        payload = body.model_dump()
        target = payload.pop("target_stage")
        from .vendor_profile import effect_guard
        return _jsonable(
            await call(ops, store.transition_lifecycle, tenant, lifecycle_id, target, **payload,
                effect_guard=effect_guard(request, tenant, _principal_ref, family="lifecycle", admin=target == "suspended"))
        )

    @router.post("/lifecycles/{lifecycle_id}/offboarding/{plan_id}")
    async def begin_offboarding(
        request: Request, lifecycle_id: ObjectPath, plan_id: ObjectPath, body: BeginOffboardingIn
    ):
        require_global_permission(request, "admin")
        if not (caller_principal(request) or "").startswith("user:"):
            raise HTTPException(403, "Set up individual sign-ins before starting offboarding approval.")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.begin_offboarding, tenant, lifecycle_id, plan_id, **body.model_dump()
            )
        )

    @router.get("/offboarding/{plan_id}")
    async def get_offboarding(request: Request, plan_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.get_offboarding_plan, tenant, plan_id))

    @router.post("/offboarding/{plan_id}/legal-hold")
    async def set_legal_hold(request: Request, plan_id: ObjectPath, body: LegalHoldIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.set_legal_hold, tenant, plan_id, **body.model_dump())
        )

    @router.put("/offboarding/{plan_id}/tasks/{task_id}")
    async def set_offboarding_task(
        request: Request, plan_id: ObjectPath, task_id: ObjectPath, body: OffboardingTaskIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.set_offboarding_task, tenant, plan_id, task_id, **body.model_dump()
            )
        )

    @router.post("/offboarding/{plan_id}/complete")
    async def complete_offboarding(
        request: Request, plan_id: ObjectPath, body: IndependentCompletionIn
    ):
        require_global_permission(request, "admin")
        if not (caller_principal(request) or "").startswith("user:"):
            raise HTTPException(403, "Sign in with an individual account to approve offboarding.")
        ops, tenant, _principal_ref, store = authority(request)
        plan = await call(ops, store.get_offboarding_plan, tenant, plan_id)
        if _unattributed_author(tenant, plan.initiated_by):
            raise HTTPException(
                409,
                "This offboarding plan began before individual sign-ins. Start a new plan while signed in, then ask another administrator to approve completion.",
            )
        return _jsonable(
            await call(
                ops, store.approve_offboarding_completion, tenant, plan_id, **body.model_dump()
            )
        )

    @router.get("/callbacks/{callback_id}")
    async def get_callback(request: Request, callback_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        result = _jsonable(await call(ops, store.get_callback, tenant, callback_id))
        result.pop("lease_token", None)
        return result

    @router.post("/callbacks/claim")
    async def claim_callbacks(request: Request, body: ClaimCallbacksIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return {
            "items": _jsonable(await call(ops, store.claim_callbacks, tenant, **body.model_dump()))
        }

    @router.post("/callbacks/{callback_id}/fail")
    async def fail_callback(request: Request, callback_id: ObjectPath, body: FailCallbackIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.fail_callback, tenant, callback_id, **body.model_dump())
        )

    @router.post("/callbacks/{callback_id}/acknowledge")
    async def acknowledge_callback(request: Request, callback_id: ObjectPath, body: AckCallbackIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.acknowledge_callback, tenant, callback_id, **body.model_dump())
        )

    @router.post("/callbacks/{callback_id}/requeue")
    async def requeue_callback(request: Request, callback_id: ObjectPath, body: RequeueCallbackIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(ops, store.requeue_dead_letter, tenant, callback_id, **body.model_dump())
        )

    @router.put("/assessments/{assessment_id}/exports/{export_id}")
    async def export_assessment(
        request: Request, assessment_id: ObjectPath, export_id: ObjectPath, body: ExportIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.export_assessment, tenant, assessment_id, export_id, **body.model_dump()
            )
        )

    @router.put("/lifecycles/{lifecycle_id}/exports/{export_id}")
    async def export_lifecycle(
        request: Request, lifecycle_id: ObjectPath, export_id: ObjectPath, body: ExportIn
    ):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(
            await call(
                ops, store.export_lifecycle, tenant, lifecycle_id, export_id, **body.model_dump()
            )
        )

    @router.get("/exports/{export_id}")
    async def get_export(request: Request, export_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.get_export, tenant, export_id))

    @router.post("/retention/purge")
    async def purge(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store = authority(request)
        return _jsonable(await call(ops, store.purge_expired, tenant, **body.model_dump()))

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        ops, tenant, _principal_ref, store = authority(request)
        result = _jsonable(await call(ops, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_third_party_lifecycle_router()

__all__ = [
    "ThirdPartyLifecycleDependencies",
    "create_third_party_lifecycle_router",
    "router",
    "third_party_lifecycle_enabled_for_page",
]
