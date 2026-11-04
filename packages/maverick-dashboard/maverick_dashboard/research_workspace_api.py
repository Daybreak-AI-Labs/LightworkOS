"""Tenant-safe dashboard composition for governed research assets and runs.

The routes project immutable registry/run records into customer-facing JSON.
They never return dataset bytes, model weights, authority credentials, adapter
configuration, or resource-cost source locations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from maverick.knowledge_content_projection import inspect_existing_source
from maverick.paths import current_tenant_id_strict
from maverick.privacy_ops import RecordConflict
from maverick.research_registry import (
    DataUseAuthority,
    RegistryReviewAuthority,
    ResearchAssetRef,
    ResearchRegistry,
    ResearchRegistryConflict,
    ResearchRegistryDenied,
    ResearchRegistryNotFound,
    resolve_data_use_authority,
    verified_training_receipt_resolver,
)
from maverick.research_runs import (
    ResearchMaterializationUnavailable,
    ResearchResourceCaps,
    ResearchRunAuthority,
    ResearchRunConflict,
    ResearchRunInterrupted,
    ResearchRunNotFound,
    ResearchRuns,
    ResearchWorkerAuthority,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, has_global_permission, require_permission
from .draft_api import context_for


class _PrivateWorkspaceRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def private_validation(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content={"detail": "Research registry or run fields are malformed"},
                    headers={"Cache-Control": "private, no-store"},
                )

        return private_validation


router = APIRouter(route_class=_PrivateWorkspaceRoute)
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
_PURPOSE_PATTERN = r"^[a-z][a-z0-9_.-]{0,63}$"
_SHA_PATTERN = r"^[a-f0-9]{64}$"
_REVISION_PATTERN = r"^(?:[a-f0-9]{40}|[a-f0-9]{64}|sha256:[a-f0-9]{64})$"
Identifier = Annotated[str, Field(pattern=_ID_PATTERN)]
Purpose = Annotated[str, Field(pattern=_PURPOSE_PATTERN)]
Sha256 = Annotated[str, Field(pattern=_SHA_PATTERN)]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, allow_inf_nan=False, populate_by_name=True
    )


class _Reviewed(_Strict):
    context: Sha256
    confirm: bool


class AssetReference(_Strict):
    kind: Literal["dataset", "model"]
    asset_id: Identifier
    version: Identifier
    manifest_sha256: Sha256
    reference_schema: Literal["lightwork.research-registry-ref.v1"] = Field(
        "lightwork.research-registry-ref.v1", alias="schema"
    )

    def exact(self) -> ResearchAssetRef:
        return ResearchAssetRef(
            kind=self.kind,
            asset_id=self.asset_id,
            version=self.version,
            manifest_sha256=self.manifest_sha256,
            schema=self.reference_schema,
        )


class DatasetRegistration(_Reviewed):
    dataset_id: Identifier
    version: Identifier
    source_ref: str = Field(min_length=1, max_length=2048)
    content_sha256: Sha256 | None = None
    license_id: Identifier
    license_evidence_sha256: Sha256
    allowed_purposes: list[Purpose] = Field(min_length=1, max_length=64)
    usage_constraints: list[str] = Field(min_length=1, max_length=32)
    data_use_action: Literal["analyze", "export", "read", "train"]
    data_use_decision_id: Identifier
    data_use_decision_sha256: Sha256
    consent_record_id: Identifier | None = None
    consent_evidence_sha256: Sha256 | None = None
    parent_datasets: list[AssetReference] = Field(default_factory=list, max_length=128)
    provenance_kind: Literal["source", "derived", "synthetic"]
    synthetic_generator_id: Identifier | None = None
    synthetic_generator_version: Identifier | None = None
    synthetic_generator_sha256: Sha256 | None = None
    synthetic_config_sha256: Sha256 | None = None
    synthetic_seed: int | None = Field(default=None, ge=0, lt=2**63)

    @model_validator(mode="after")
    def exact_provenance(self):
        if any(ref.kind != "dataset" for ref in self.parent_datasets):
            raise ValueError("parent lineage must contain dataset versions")
        if (self.consent_record_id is None) != (self.consent_evidence_sha256 is None):
            raise ValueError("consent record and evidence must be supplied together")
        synthetic = (
            self.synthetic_generator_id,
            self.synthetic_generator_version,
            self.synthetic_generator_sha256,
            self.synthetic_config_sha256,
            self.synthetic_seed,
        )
        if self.provenance_kind == "synthetic" and any(value is None for value in synthetic):
            raise ValueError("synthetic provenance requires generator, config, artifact, and seed")
        if self.provenance_kind != "synthetic" and any(value is not None for value in synthetic):
            raise ValueError("generator fields are only valid for synthetic data")
        return self


class ModelRegistration(_Reviewed):
    model_id: Identifier
    version: Identifier
    source_ref: str = Field(min_length=1, max_length=2048)
    artifact_sha256: Sha256
    license_id: Identifier
    license_evidence_sha256: Sha256
    allowed_purposes: list[Purpose] = Field(min_length=1, max_length=64)
    usage_constraints: list[str] = Field(min_length=1, max_length=32)
    provider_model_identity: str = Field(min_length=1, max_length=256)
    immutable_provider_revision: Identifier | None = None
    observed_from: float | None = Field(default=None, gt=0)
    observed_until: float | None = Field(default=None, gt=0)
    reproducibility_limitation: str | None = Field(default=None, min_length=1, max_length=512)
    dataset_lineage: list[AssetReference] = Field(default_factory=list, max_length=128)
    dataset_lineage_purpose: Purpose | None = None
    model_lineage: list[AssetReference] = Field(default_factory=list, max_length=128)
    provenance_kind: Literal["external", "trained"]
    training_receipt_id: Identifier | None = None
    training_receipt_sha256: Sha256 | None = None
    training_dataset_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def exact_lineage(self):
        if any(ref.kind != "dataset" for ref in self.dataset_lineage):
            raise ValueError("dataset lineage contains a model")
        if any(ref.kind != "model" for ref in self.model_lineage):
            raise ValueError("model lineage contains a dataset")
        return self


class AssetMutation(_Reviewed):
    reference: AssetReference
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class AssetRevocation(AssetMutation):
    reason_code: Purpose
    evidence_sha256: Sha256


class ResourceCaps(_Strict):
    max_wall_seconds: int = Field(ge=0, le=31_536_000)
    max_provider_calls: int = Field(ge=0, le=10_000_000)
    max_storage_bytes: int = Field(ge=0, le=2**60)
    max_cost: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$", max_length=64)
    currency: str = Field(pattern=r"^[A-Z]{3,8}$")


class RunPlan(_Reviewed):
    run_id: Identifier
    run_version: Identifier
    experiment_id: Identifier
    experiment_version: Identifier
    purpose: Purpose
    action: Literal["analyze", "train"]
    code_revision: str = Field(pattern=_REVISION_PATTERN)
    code_sha256: Sha256
    environment_id: Identifier
    environment_version: Identifier
    environment_sha256: Sha256
    seed: int = Field(ge=0, lt=2**63)
    dataset_refs: list[AssetReference] = Field(min_length=1, max_length=128)
    model_ref: AssetReference | None = None
    resource_caps: ResourceCaps
    metric_protocol_sha256: Sha256
    program_id: Identifier | None = None

    @model_validator(mode="after")
    def exact_refs(self):
        if any(ref.kind != "dataset" for ref in self.dataset_refs):
            raise ValueError("a run dataset selector contains a model")
        if self.model_ref is not None and self.model_ref.kind != "model":
            raise ValueError("a run model selector contains a dataset")
        return self


class RunRevision(_Reviewed):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class ExecutionApproval(RunRevision):
    review_sha256: Sha256


class RunCancellation(RunRevision):
    reason_code: Purpose
    evidence_sha256: Sha256


def _binding(request: Request, response: Response, payload: _Reviewed | None = None):
    require_permission(request, "operate")
    actor, tenant = caller_principal(request), current_tenant_id_strict()
    if not actor or not actor.startswith("user:") or not tenant:
        raise HTTPException(403, "Sign in with a named account and select a research workspace")
    response.headers["Cache-Control"] = "private, no-store"
    context = context_for(request)
    if payload is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Account or workspace changed; reload the research lab")
        if payload.confirm is not True:
            raise HTTPException(422, "Review and confirm this research action")
    return tenant, actor, context


def _registry_review_authority(tenant: str, principal: str) -> RegistryReviewAuthority:
    from .research_api import resolve_dispatch_authority

    current = resolve_dispatch_authority(tenant, principal)
    return RegistryReviewAuthority(tenant, principal, current.authorization_sha256)


def _run_authority(tenant: str, principal: str) -> ResearchRunAuthority:
    from .research_api import resolve_authority

    current = resolve_authority(tenant, principal)
    return ResearchRunAuthority(tenant, principal, current.authorization_sha256)


def _worker_authority(tenant: str, principal: str) -> ResearchWorkerAuthority:
    from .research_api import resolve_authority

    current = resolve_authority(tenant, principal)
    return ResearchWorkerAuthority(tenant, principal, current.authorization_sha256)


def _review_authority(tenant: str, principal: str) -> ResearchWorkerAuthority:
    from .research_api import resolve_dispatch_authority

    current = resolve_dispatch_authority(tenant, principal)
    return ResearchWorkerAuthority(tenant, principal, current.authorization_sha256)


def _server_training_receipt(tenant: str, receipt_id: str):
    from maverick.training.receipts import server_training_trust_registries

    receipt_keys, approver_keys = server_training_trust_registries()
    resolver = verified_training_receipt_resolver(
        trusted_receipt_pubkeys=receipt_keys,
        trusted_approver_pubkeys=approver_keys,
    )
    return resolver(tenant, receipt_id)


def _registry_service(state=None) -> ResearchRegistry:
    consent = getattr(state, "research_registry_consent_resolver", None)
    receipt = getattr(state, "research_training_receipt_resolver", None)
    return ResearchRegistry(
        consent_resolver=consent if callable(consent) else None,
        review_authority_resolver=_registry_review_authority,
        training_receipt_resolver=(receipt if callable(receipt) else _server_training_receipt),
    )


def _run_service(state=None) -> ResearchRuns:
    adapter = getattr(state, "research_run_effect_adapter", None)
    if adapter is None:
        from .research_execution_composition import PackagedResearchExecution
        adapter = PackagedResearchExecution()
    shared_guard = getattr(state, "research_run_shared_effect_guard", None)
    return ResearchRuns(
        registry=_registry_service(state),
        authority_resolver=_run_authority,
        worker_authority_resolver=_worker_authority,
        review_authority_resolver=_review_authority,
        effect_adapter=adapter,
        shared_effect_guard=shared_guard if callable(shared_guard) else None,
    )


async def _call(function: Callable, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (ResearchRegistryNotFound, ResearchRunNotFound) as exc:
        raise HTTPException(404, "Research record was not found in this workspace") from exc
    except (ResearchRegistryConflict, ResearchRunConflict, RecordConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except ResearchRegistryDenied as exc:
        raise HTTPException(409, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(403, "Current research workspace authority is required") from exc
    except ResearchMaterializationUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ResearchRunInterrupted as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - do not disclose storage or adapter internals
        raise HTTPException(503, "Governed research state is unavailable") from exc


def _approval(value):
    if not isinstance(value, dict):
        return None
    return {
        key: value.get(key)
        for key in ("approved_by", "approved_at", "approval_sha256", "manifest_sha256")
    }


def _revocation(value):
    if not isinstance(value, dict):
        return None
    return {
        key: value.get(key)
        for key in ("revoked_by", "revoked_at", "reason_code", "evidence_sha256")
    }


def _asset_projection(value: dict) -> dict:
    manifest = value["manifest"]
    reference = value["reference"]
    common = {
        "reference": reference,
        "kind": reference["kind"],
        "state": value["state"],
        "revision": value["revision"],
        "registered_by": value["registered_by"],
        "created_at": value["created_at"],
        "updated_at": value["updated_at"],
        "source_ref": manifest["source_ref"],
        "license_id": manifest["license_id"],
        "license_evidence_sha256": manifest["license_evidence_sha256"],
        "allowed_purposes": manifest["allowed_purposes"],
        "usage_constraints": manifest["usage_constraints"],
        "provenance_kind": manifest["provenance_kind"],
        "approval": _approval(value.get("approval")),
        "revocation": _revocation(value.get("revocation")),
        "eligibility": {
            "state": (
                "awaiting_approval"
                if value["state"] == "draft"
                else "revoked"
                if value["state"] == "revoked"
                else "not_checked"
            ),
            "checked_purposes": [],
        },
    }
    if reference["kind"] == "dataset":
        common.update(
            content_sha256=manifest["content_sha256"],
            data_use_action=manifest["data_use_action"],
            data_use_decision_id=manifest["data_use_decision_id"],
            data_use_decision_sha256=manifest["data_use_decision_sha256"],
            consent_record_id=manifest["consent_record_id"],
            consent_evidence_sha256=manifest["consent_evidence_sha256"],
            parent_datasets=manifest["parent_datasets"],
            synthetic_provenance=manifest["synthetic_provenance"],
        )
    else:
        common.update(
            artifact_sha256=manifest["artifact_sha256"],
            provider_model_identity=manifest["provider_model_identity"],
            immutable_provider_revision=manifest["immutable_provider_revision"],
            observed_from=manifest["observed_from"],
            observed_until=manifest["observed_until"],
            reproducibility_limitation=manifest["reproducibility_limitation"],
            dataset_lineage=manifest["dataset_lineage"],
            dataset_lineage_purpose=manifest["dataset_lineage_purpose"],
            model_lineage=manifest["model_lineage"],
            training_receipt_id=manifest["training_receipt_id"],
            training_receipt_sha256=manifest["training_receipt_sha256"],
            training_dataset_sha256=manifest["training_dataset_sha256"],
        )
    return common


def _asset_projection_with_eligibility(
    registry: ResearchRegistry, tenant: str, value: dict
) -> dict:
    result = _asset_projection(value)
    if value["state"] != "approved":
        return result
    reference = ResearchAssetRef(**value["reference"])
    purposes = tuple(value["manifest"]["allowed_purposes"])
    try:
        if reference.kind == "dataset":
            for purpose in purposes:
                registry.resolve_dataset(
                    tenant,
                    reference,
                    purpose=purpose,
                    action=str(value["manifest"]["data_use_action"]),
                )
        else:
            for purpose in purposes:
                registry.resolve_model(tenant, reference, purpose=purpose)
    except (ResearchRegistryDenied, ResearchRegistryConflict):
        result["eligibility"] = {
            "state": "blocked",
            "checked_purposes": list(purposes),
            "detail": "Current rights, consent, approval, or lineage no longer permits use.",
        }
    except Exception:  # noqa: BLE001 - availability is projected without leaking authority details
        result["eligibility"] = {
            "state": "unavailable",
            "checked_purposes": list(purposes),
            "detail": "Current rights could not be revalidated.",
        }
    else:
        result["eligibility"] = {
            "state": "eligible",
            "checked_purposes": list(purposes),
            "detail": "Current approval, rights, consent, and lineage checks passed.",
        }
    return result


def _safe_cost_event(value: dict) -> dict:
    cost = dict(value.get("cost") or {})
    source_ref = str(cost.pop("source_ref", ""))
    cost["source_ref_sha256"] = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()
    return {
        key: value.get(key)
        for key in (
            "sequence",
            "event_key",
            "recorded_at",
            "recorded_by",
            "correction_of",
            "previous_event_sha256",
            "event_sha256",
        )
    } | {"cost": cost}


def _safe_terminal(value):
    if not isinstance(value, dict):
        return value
    result = {
        key: item
        for key, item in value.items()
        if key not in {"costs", "training_receipt_authority"}
    }
    costs = []
    for raw in value.get("costs", ()):
        cost = dict(raw) if isinstance(raw, dict) else {}
        source_ref = str(cost.pop("source_ref", ""))
        cost["source_ref_sha256"] = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()
        costs.append(cost)
    result["costs"] = costs
    return result


def _run_projection(value: dict, actor: str | None = None) -> dict:
    manifest = dict(value["manifest"])
    attempts = []
    for item in value["attempts"]:
        receipt = item.get("dispatch_receipt")
        attempts.append(
            {
                "number": item["number"],
                "status": item["status"],
                "version_binding": item["version_binding"],
                "registry_binding_sha256": (
                    None
                    if not isinstance(item.get("registry_binding"), dict)
                    else item["registry_binding"].get("binding_sha256")
                ),
                "dispatch": (
                    None
                    if not isinstance(receipt, dict)
                    else {
                        key: receipt.get(key)
                        for key in ("dispatch_id", "request_sha256", "dispatched_at")
                    }
                ),
                "terminal": _safe_terminal(item.get("terminal")),
                "events": item["events"],
                "costs": [_safe_cost_event(event) for event in item["costs"]],
                "metrics": item["metrics"],
                "execution": item.get("execution"),
                "stop_requested": item.get("stop_requested") is True,
                "execution_owner": (item.get("worker_authority") or {}).get("principal"),
                "execution_approval": ({key: item["execution_approval"].get(key) for key in
                    ("reviewer", "review_sha256", "expires_at")} if item.get("execution_approval") else None),
            }
        )
    return {
        "run_id": value["run_id"],
        "created_by": value["created_by"],
        "manifest": manifest,
        "manifest_sha256": value["manifest_sha256"],
        "status": value["status"],
        "revision": value["revision"],
        "created_at": value["created_at"],
        "updated_at": value["updated_at"],
        "attempts": attempts,
        "cost_summary": value.get("cost_summary"),
        "can_stop": value["status"] == "running" and (value["attempts"][-1].get("worker_authority") or {}).get("principal") == actor,
        "can_start": value["status"] == "queued" and (value["attempts"][-1].get("execution_approval") or {}).get("reviewer") == actor,
        "can_manage": value["created_by"] == actor,
    }


def _adapter_available(state) -> bool:
    adapter = getattr(state, "research_run_effect_adapter", None)
    if adapter is not None:
        return callable(getattr(adapter, "materialize_and_dispatch", None))
    try:
        from maverick.research_jobs import configured_profile
        configured_profile()
        return True
    except Exception:
        return False


def _data_use_choices(tenant: str) -> dict:
    """Project currently authorized allow decisions without exposing controls."""

    try:
        from maverick import config
        from maverick.data_use_governance import DataUseGovernanceStore
        from maverick.data_use_policy_compiler import DataUseCompilationStale
        from maverick.governed_records import configured_governed_records_backend
        from maverick.paths import data_dir

        if not config.data_use_governance_enabled():
            return {"state": "disabled", "items": [], "truncated": False}
        if configured_governed_records_backend() != "local":
            return {"state": "shared_adapter_required", "items": [], "truncated": False}
        store = DataUseGovernanceStore(
            data_dir(
                "data_use_governance",
                "data-use-governance.sqlite3",
                tenant=tenant,
            )
        )
        rows = store.list_records(tenant, "decision", limit=101)
        items = []
        for row in rows:
            if row.get("outcome") != "allow":
                continue
            decision_id = row.get("decision_id")
            decision_sha256 = row.get("decision_sha256")
            if (
                not isinstance(decision_id, str)
                or re.fullmatch(_ID_PATTERN, decision_id) is None
                or not isinstance(decision_sha256, str)
                or re.fullmatch(_SHA_PATTERN, decision_sha256) is None
            ):
                raise ValueError("data-use decision projection is malformed")
            try:
                authority = resolve_data_use_authority(
                    tenant,
                    decision_id,
                    decision_sha256,
                )
            except (ResearchRegistryDenied, DataUseCompilationStale):
                # Stale, expired, withdrawn, or source-drifted decisions remain
                # in their forensic ledger but are not offered for a new asset.
                continue
            if type(authority) is not DataUseAuthority:
                raise ValueError("data-use decision projection is malformed")
            items.append(
                {
                    "decision_id": authority.decision_id,
                    "decision_sha256": authority.decision_sha256,
                    "asset_id": authority.asset_id,
                    "action": authority.action,
                    "purpose_codes": list(authority.purpose_codes),
                    "expires_at": authority.expires_at,
                }
            )
        items.sort(key=lambda item: (str(item["asset_id"]), str(item["decision_id"])))
        return {"state": "available", "items": items[:100], "truncated": len(rows) > 100}
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return {"state": "unavailable", "items": [], "truncated": False}


async def _current_run(service: ResearchRuns, tenant: str, actor: str, result: dict) -> dict:
    current = await _call(service.inspect, tenant, actor, str(result["run_id"]))
    return _run_projection(current, actor)


async def workspace_overview(request: Request, tenant: str, actor: str) -> dict:
    registry = _registry_service(request.app.state)
    datasets = await _call(registry.list, tenant, kind="dataset", limit=101)
    models = await _call(registry.list, tenant, kind="model", limit=101)
    runs = await _call(_run_service(request.app.state).list, tenant, actor, limit=101)
    decisions = await run_in_threadpool(_data_use_choices, tenant)
    projected_datasets = await run_in_threadpool(
        lambda: [
            _asset_projection_with_eligibility(registry, tenant, row) for row in datasets[:100]
        ]
    )
    projected_models = await run_in_threadpool(
        lambda: [_asset_projection_with_eligibility(registry, tenant, row) for row in models[:100]]
    )
    return {
        "registry": {
            "datasets": projected_datasets,
            "models": projected_models,
            "truncated": len(datasets) > 100 or len(models) > 100,
            "can_review": has_global_permission(request, "admin"),
            "consent_authority_available": callable(
                getattr(request.app.state, "research_registry_consent_resolver", None)
            ),
            "training_receipt_verification": "server_policy_on_demand",
            "data_use_decisions": decisions,
        },
        "governed_runs": [_run_projection(row, actor) for row in runs[:100]],
        "governed_runs_truncated": len(runs) > 100,
        "governed_execution": {
            "available": _adapter_available(request.app.state),
            "state": "configured" if _adapter_available(request.app.state) else "unavailable",
            "detail": (
                "The installed local container executor is available for supported text snapshots and saved programs. Complete the independent review before Start."
                if _adapter_available(request.app.state)
                else "Set up the installed local container and its correct-output checks before running experiments. Unsupported inputs are refused before Start."
            ),
        },
    }


@router.post("/registry/datasets", status_code=201)
async def register_dataset(payload: DatasetRegistration, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    registry = _registry_service(request.app.state)
    values = payload.model_dump(exclude={"context", "confirm", "parent_datasets"})
    source_ref = payload.source_ref.strip()
    if source_ref.startswith(
        (
            "catalog:evidence-graph/",
            "catalog:fleet-memory/",
            "catalog:vector-knowledge/",
            "catalog:work-discovery/",
            "catalog:knowledge-correction/",
        )
    ):
        if not has_global_permission(request, "admin"):
            raise HTTPException(
                403,
                "An installation administrator must inspect an installed knowledge source",
            )
        await _call(
            registry.preflight_dataset_ingestion,
            tenant,
            dataset_id=payload.dataset_id,
            allowed_purposes=tuple(payload.allowed_purposes),
            data_use_action=payload.data_use_action,
            data_use_decision_id=payload.data_use_decision_id,
            data_use_decision_sha256=payload.data_use_decision_sha256,
            consent_record_id=payload.consent_record_id,
            consent_evidence_sha256=payload.consent_evidence_sha256,
        )
        inspected = await _call(inspect_existing_source, tenant, source_ref)
        resolved_sha256 = str(inspected["content_sha256"])
        if payload.content_sha256 is not None and not hmac.compare_digest(
            payload.content_sha256,
            resolved_sha256,
        ):
            raise HTTPException(
                409,
                "The installed source changed; review its current commitment before registering",
            )
        values["content_sha256"] = resolved_sha256
    elif payload.content_sha256 is None:
        raise HTTPException(
            422,
            "A content SHA-256 is required for sources without an installed exact projector",
        )
    values["source_ref"] = source_ref
    values["parent_datasets"] = tuple(item.exact() for item in payload.parent_datasets)
    reference = await _call(
        registry.register_dataset,
        tenant,
        actor,
        **values,
    )
    view = await _call(registry.inspect, tenant, reference)
    return _asset_projection(view)


@router.post("/registry/models", status_code=201)
async def register_model(payload: ModelRegistration, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    values = payload.model_dump(exclude={"context", "confirm", "dataset_lineage", "model_lineage"})
    values["dataset_lineage"] = tuple(item.exact() for item in payload.dataset_lineage)
    values["model_lineage"] = tuple(item.exact() for item in payload.model_lineage)
    reference = await _call(
        _registry_service(request.app.state).register_model,
        tenant,
        actor,
        **values,
    )
    view = await _call(_registry_service(request.app.state).inspect, tenant, reference)
    return _asset_projection(view)


@router.post("/registry/approve")
async def approve_asset(payload: AssetMutation, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    if not has_global_permission(request, "admin"):
        raise HTTPException(
            403, "A named installation administrator must approve registry versions"
        )
    registry = _registry_service(request.app.state)
    reference = await _call(
        registry.approve,
        tenant,
        actor,
        payload.reference.exact(),
        expected_revision=payload.expected_revision,
    )
    view = await _call(registry.inspect, tenant, reference)
    return await run_in_threadpool(_asset_projection_with_eligibility, registry, tenant, view)


@router.post("/registry/revoke")
async def revoke_asset(payload: AssetRevocation, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    if not has_global_permission(request, "admin"):
        raise HTTPException(403, "A named installation administrator must revoke registry versions")
    registry = _registry_service(request.app.state)
    reference = await _call(
        registry.revoke,
        tenant,
        actor,
        payload.reference.exact(),
        expected_revision=payload.expected_revision,
        reason_code=payload.reason_code,
        evidence_sha256=payload.evidence_sha256,
    )
    view = await _call(registry.inspect, tenant, reference)
    return await run_in_threadpool(_asset_projection_with_eligibility, registry, tenant, view)


@router.get("/registry/{kind}/{asset_id}/{version}/impact")
async def asset_impact(
    kind: Literal["dataset", "model"],
    asset_id: Identifier,
    version: Identifier,
    request: Request,
    response: Response,
    manifest_sha256: Sha256 = Query(...),
):
    tenant, _, _ = _binding(request, response)
    value = await _call(
        _registry_service(request.app.state).derivative_impact,
        tenant,
        ResearchAssetRef(kind, asset_id, version, manifest_sha256),
    )
    return value


@router.post("/governed-runs", status_code=201)
async def plan_run(payload: RunPlan, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    values = payload.model_dump(
        exclude={"context", "confirm", "dataset_refs", "model_ref", "resource_caps"}
    )
    values["dataset_refs"] = tuple(item.exact() for item in payload.dataset_refs)
    values["model_ref"] = None if payload.model_ref is None else payload.model_ref.exact()
    values["resource_caps"] = ResearchResourceCaps(**payload.resource_caps.model_dump())
    service = _run_service(request.app.state)
    result = await _call(service.plan, tenant, actor, **values)
    return await _current_run(service, tenant, actor, result)


@router.get("/execution-options")
async def execution_options(request: Request, response: Response):
    tenant, actor, context = _binding(request, response)
    from maverick.research_jobs import configured_profile

    from .research_execution_composition import program_choices
    try:
        profile = await _call(configured_profile)
    except HTTPException as exc:
        return {"context": context, "available": False, "programs": [],
                "detail": "Complete Administrator setup for the installed local container and its correct-output check.", "status": exc.status_code}
    programs = await _call(program_choices, tenant, actor)
    return {"context": context, "available": True, "programs": programs,
            "environment": "Installed local container", "timeout_seconds": profile.limits.timeout_seconds,
            "detail": "Select a saved program submission. The installed executor supports exact local text snapshots, no model or paid AI calls. A different administrator reviews every program file before separately starting it."}


@router.get("/governed-runs/{run_id}/execution-review")
async def execution_review(run_id: Identifier, request: Request, response: Response):
    tenant, actor, context = _binding(request, response)
    from .research_api import resolve_dispatch_authority
    from .research_execution_composition import complete_review
    await _call(resolve_dispatch_authority, tenant, actor)
    service = _run_service(request.app.state)
    record = await _call(service.inspect, tenant, actor, run_id)
    result = await _call(complete_review, service, record, actor)
    return {"context": context, **result}


@router.post("/governed-runs/{run_id}/approve-execution")
async def approve_execution(run_id: Identifier, payload: ExecutionApproval, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    from .research_api import resolve_dispatch_authority
    from .research_execution_composition import review_binding
    await _call(resolve_dispatch_authority, tenant, actor)
    service = _run_service(request.app.state)
    result = await _call(service.approve_execution, tenant, actor, run_id,
        expected_revision=payload.expected_revision,review_sha256=payload.review_sha256,
        review=lambda record, reviewer: review_binding(service,record,reviewer))
    return await _current_run(service, tenant, actor, result)


@router.get("/governed-runs/{run_id}/original")
async def execution_original(run_id: Identifier, request: Request, response: Response):
    """Pure existing run lookup; never start, finish or replay a candidate."""
    tenant, actor, context = _binding(request, response)
    result = await _call(_run_service(request.app.state).inspect, tenant, actor, run_id)
    return {"context":context,"run":_run_projection(result, actor),"historical":True,
            "message":"This is the retained original run. Running or interrupted work is never started again by this read."}


@router.post("/governed-runs/{run_id}/stop")
async def execution_stop(run_id: Identifier, payload: RunRevision, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    from .research_api import resolve_dispatch_authority
    await _call(resolve_dispatch_authority, tenant, actor)
    service = _run_service(request.app.state)
    result = await _call(service.stop_execution,tenant,actor,run_id,expected_revision=payload.expected_revision)
    return await _current_run(service, tenant, actor, result)


@router.get("/governed-runs/{run_id}")
async def inspect_run(run_id: Identifier, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response)
    result = await _call(_run_service(request.app.state).inspect, tenant, actor, run_id)
    return _run_projection(result)


@router.post("/governed-runs/{run_id}/queue")
async def queue_run(run_id: Identifier, payload: RunRevision, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    service = _run_service(request.app.state)
    result = await _call(
        service.queue,
        tenant,
        actor,
        run_id,
        expected_revision=payload.expected_revision,
    )
    return await _current_run(service, tenant, actor, result)


@router.post("/governed-runs/{run_id}/start")
async def start_run(run_id: Identifier, payload: RunRevision, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    service = _run_service(request.app.state)
    result = await _call(
        service.start,
        tenant,
        actor,
        run_id,
        expected_revision=payload.expected_revision,
    )
    return await _current_run(service, tenant, actor, result)


@router.post("/governed-runs/{run_id}/retry")
async def retry_run(run_id: Identifier, payload: RunRevision, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response, payload)
    service = _run_service(request.app.state)
    result = await _call(
        service.retry,
        tenant,
        actor,
        run_id,
        expected_revision=payload.expected_revision,
    )
    return await _current_run(service, tenant, actor, result)


@router.post("/governed-runs/{run_id}/cancel")
async def cancel_run(
    run_id: Identifier, payload: RunCancellation, request: Request, response: Response
):
    tenant, actor, _ = _binding(request, response, payload)
    service = _run_service(request.app.state)
    result = await _call(
        service.cancel,
        tenant,
        actor,
        run_id,
        expected_revision=payload.expected_revision,
        reason_code=payload.reason_code,
        evidence_sha256=payload.evidence_sha256,
    )
    return await _current_run(service, tenant, actor, result)


@router.get("/governed-runs/{run_id}/export")
async def export_run(run_id: Identifier, request: Request, response: Response):
    tenant, actor, _ = _binding(request, response)
    content = await _call(_run_service(request.app.state).export, tenant, actor, run_id)
    # Parse once so a corrupted/non-canonical adapter cannot smuggle non-JSON
    # bytes through this customer-facing evidence route.
    try:
        parsed = json.loads(content)
        source_canonical = json.dumps(
            parsed,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(503, "Research evidence export is malformed") from exc
    if not hmac.compare_digest(content, source_canonical):
        raise HTTPException(503, "Research evidence export is not canonical")
    if (
        not isinstance(parsed, dict)
        or not isinstance(parsed.get("run"), dict)
        or not isinstance(parsed.get("cost_summary"), dict)
        or not isinstance(parsed.get("data_statement"), dict)
    ):
        raise HTTPException(503, "Research evidence export is malformed")
    safe_run = dict(parsed["run"])
    safe_run["cost_summary"] = parsed["cost_summary"]
    parsed = {
        "schema": parsed.get("schema"),
        "run": _run_projection(safe_run),
        "cost_summary": parsed["cost_summary"],
        "data_statement": parsed["data_statement"],
        "projection_statement": {
            "contains_authority_credentials": False,
            "contains_resource_cost_source_locations": False,
            "resource_cost_source_locations_represented_by_sha256": True,
        },
    }
    canonical = json.dumps(
        parsed,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return Response(
        content=canonical,
        media_type="application/json",
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": f'attachment; filename="research-run-{run_id}.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )


__all__ = ["router", "workspace_overview"]
