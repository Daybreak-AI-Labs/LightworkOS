"""Strict authenticated API for the tenant-private no-code GRC studio."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
OpaqueId = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN)
]
ObjectPath = Annotated[str, ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN)]
OperationId = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN)
]
Digest = Annotated[
    str, StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN)
]
State = Literal["draft", "in_review", "reviewed", "rejected", "approved", "published", "superseded"]
ProjectionKind = Literal["questionnaire", "collector", "report"]

_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_REQUIRED_STORE_METHODS = (
    "create_version",
    "replace_draft",
    "submit_for_review",
    "review",
    "approve",
    "publish",
    "rollback",
    "get_version",
    "get_active",
    "list_versions",
    "history",
    "export_version",
    "import_version",
    "preview_projection",
    "apply_projection",
    "retention_due",
    "purge_expired",
    "verify_integrity",
    "create_recovery_backup",
    "verify_recovery_backup",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateVersionIn(_StrictModel):
    blueprint: dict[str, Any]
    expected_latest_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    operation_id: OperationId


class ReplaceDraftIn(_StrictModel):
    blueprint: dict[str, Any]
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_integrity_sha256: Digest
    operation_id: OperationId


class VersionCASIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_integrity_sha256: Digest
    operation_id: OperationId


class ReviewIn(VersionCASIn):
    accepted: StrictBool
    rationale_ref: OpaqueId


class ApproveIn(VersionCASIn):
    approval_ref: OpaqueId


class PublishIn(VersionCASIn):
    expected_active_version: int = Field(strict=True, ge=0, le=2_147_483_647)
    expected_active_blueprint_sha256: Digest | None = None
    expected_pointer_revision: int = Field(strict=True, ge=0, le=2_147_483_647)


class RollbackIn(_StrictModel):
    target_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_target_blueprint_sha256: Digest
    expected_active_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_active_blueprint_sha256: Digest
    expected_pointer_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    rationale_ref: OpaqueId
    operation_id: OperationId


class ExportIn(_StrictModel):
    studio_id: OpaqueId
    version: int = Field(strict=True, ge=1, le=2_147_483_647)
    operation_id: OperationId


class ImportIn(_StrictModel):
    envelope: dict[str, Any]
    expected_latest_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    operation_id: OperationId


class ProjectionIn(_StrictModel):
    studio_id: OpaqueId
    projection_kind: ProjectionKind
    definition_id: OpaqueId
    target_id: OpaqueId
    target_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_active_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    expected_blueprint_sha256: Digest


class ApplyProjectionIn(ProjectionIn):
    operation_id: OperationId


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=1_000)


class GRCStudioDependencies:
    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
        target_authority_resolver_factory: Callable[..., Any] | None = None,
        projection_applier_factory: Callable[..., Any] | None = None,
    ) -> None:
        for dependency in (
            store_factory,
            enabled_probe,
            readiness_probe,
            target_authority_resolver_factory,
            projection_applier_factory,
        ):
            if dependency is not None and not callable(dependency):
                raise TypeError("GRC studio dependency must be callable")
        self.store_factory = store_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe
        self.target_authority_resolver_factory = target_authority_resolver_factory
        self.projection_applier_factory = projection_applier_factory


def _ops():
    from maverick import no_code_grc_studio as studio

    return studio


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409, detail="select an active tenant before using the GRC studio"
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for the GRC studio",
    )
    digest = hashlib.sha256(
        f"lightwork.no-code-grc-studio.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"grc-studio-principal-{digest[:40]}"


_ID_RE = re.compile(_ID_PATTERN)
_DIGEST_RE = re.compile(_DIGEST_PATTERN)
_MAX_SOURCES = 500
_EVIDENCE_OUTPUTS = (
    {"path": ["status"], "label": "Check result", "type": "text_ref"},
    {"path": ["reason_code"], "label": "Result explanation", "type": "text_ref"},
    {"path": ["evidence_sha256"], "label": "Evidence file reference", "type": "digest"},
    {"path": ["source_revision_sha256"], "label": "Source edition reference", "type": "digest"},
)
_LOCAL_CONTROL_LABELS = {
    "audit_log": "Activity log",
    "audit_signing_key": "Activity log signing",
    "capability_enforcement": "Approved action permissions",
    "data_subject_export": "Personal data exports",
    "encryption_at_rest": "Stored data protection",
    "oidc_auth": "Company sign-in",
    "tenant_isolation": "Workspace separation",
    "usage_quotas": "Usage limits",
}


def _approved_collectors(request: Request, tenant: str) -> list[dict[str, object]]:
    """Current installed, approved definitions; no credentials or provider data."""
    from maverick import trc_continuous_evidence as evidence

    from . import auth, grc_draft_changes, trc_setup_api
    from .app import require_page_visible

    authority = grc_draft_changes.authority(request)
    auth.require_page_permission(request, "/compliance/continuous-evidence")
    require_page_visible(request, "/compliance/continuous-evidence")
    if authority[0] != tenant or not auth.suite_allowed(request, "it_grc"):
        raise HTTPException(403, "Your current access does not permit these evidence sources.")
    try:
        _, selected_tenant, store = trc_setup_api._store(request)
        plans = trc_setup_api._manifests(request, tenant)
        if selected_tenant != tenant or len(plans) > _MAX_SOURCES:
            raise HTTPException(503, "The complete approved evidence source list is unavailable. Your entered work is kept.")
        labels = trc_setup_api._source_controls()
        result = []
        for plan in plans.values():
            try:
                definition = store.get_definition(plan["definition_id"], plan["definition_version"])
            except evidence.ContinuousEvidenceNotFound:
                continue  # Configured but not yet saved and independently approved.
            if definition.state != "approved" or plan["credential_ready"] is False:
                continue
            controls = sorted(set(definition.allowed_control_refs) & set(plan["controls"]))
            # Blueprint control references use a narrower declared identifier grammar.
            controls = [identifier for identifier in controls if _ID_RE.fullmatch(identifier)]
            retained_labels = (definition.source_manifest or {}).get("control_labels", {})
            result.append({
                "collector_id": definition.collector_id,
                "collector_version": definition.version,
                "collector_integrity_sha256": definition.integrity_sha256,
                "label": plan["label"], "definition_id": definition.definition_id,
                "outputs": list(_EVIDENCE_OUTPUTS),
                "controls": [{"value": identifier, "label": retained_labels.get(identifier) or labels.get(identifier) or _LOCAL_CONTROL_LABELS.get(identifier) or
                              identifier.replace("_", " ").replace("-", " ")} for identifier in controls],
            })
    except (evidence.ContinuousEvidenceError, OSError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(503, "Current evidence sources could not be verified. Your entered work is kept.") from exc
    if grc_draft_changes.authority(request) != authority:
        raise HTTPException(409, "Your account, workspace or access changed. Read the current evidence choices again.")
    return result


def validate_collector_bindings(request: Request, blueprint: Mapping, previous: Mapping | None = None) -> list:
    """Pin supported native sources through the existing final writer guard.

    Custom-adapter declarations keep their existing native contract; this does
    not invent verified choices for an uninstalled custom collector.
    """
    from maverick.trc_evidence_collectors import LocalSoc2Collector
    from maverick.trc_stock_evidence_collectors import STOCK_COLLECTOR_IDS

    bindings = blueprint.get("collector_bindings", ())
    if not bindings:
        return []
    known = {*STOCK_COLLECTOR_IDS, LocalSoc2Collector.collector_id}
    prior = (previous or {}).get("collector_bindings", ())
    current = None
    for binding in bindings:
        if binding["collector_id"] not in known:
            continue  # Preserve native custom-adapter declarations; the guided picker does not claim them.
        if current is None:
            current = _approved_collectors(request, _tenant_id())
        source = next((row for row in current if
                       row["collector_id"] == binding["collector_id"] and
                       row["collector_version"] == binding["collector_version"] and
                       row["collector_integrity_sha256"] == binding["collector_integrity_sha256"]), None)
        if source is None:
            raise HTTPException(409, "An evidence source changed or is no longer approved and available. Your draft is kept; choose its current setup before saving.")
        if not set(binding["control_refs"]) <= {row["value"] for row in source["controls"]}:
            raise HTTPException(409, "A selected control is no longer supported by this evidence source. Your entered work is kept.")
        if binding not in prior and any(mapping["source_path"] not in [row["path"] for row in source["outputs"]]
                                        for mapping in binding["field_mappings"]):
            raise HTTPException(422, "Choose a named result field from this evidence source. Custom provider-data locations are not supported here.")
    return current or []


def _listed_targets(resolver: object, tenant: str) -> tuple[list[dict[str, object]], bool]:
    """Destinations the deployment's target adapter chooses to list.

    Listing is optional: an adapter without ``list_targets`` still resolves
    typed destinations, so the page keeps a by-hand fallback.
    """
    lister = getattr(resolver, "list_targets", None)
    if not callable(lister):
        return [], False
    raw = lister(tenant)
    targets: list[dict[str, object]] = []
    for item in raw if isinstance(raw, (list, tuple)) else ():
        if not isinstance(item, Mapping) or len(targets) >= _MAX_SOURCES:
            continue
        kind, target, revision = item.get("target_kind"), item.get("target_id"), item.get("target_revision")
        if (
            kind not in {"questionnaire", "collector", "report"}
            or not isinstance(target, str)
            or not _ID_RE.fullmatch(target)
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or not 1 <= revision <= 2_147_483_647
        ):
            continue
        label = item.get("label")
        targets.append(
            {
                "target_kind": kind,
                "target_id": target,
                "target_revision": revision,
                "label": label.strip()[:120] if isinstance(label, str) and label.strip() else None,
            }
        )
    return targets, True


def _dependency(request: Request, name: str, fallback: object) -> object:
    return getattr(request.app.state, name, fallback)


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_no_code_grc_studio_router(  # noqa: C901, PLR0915
    dependencies: GRCStudioDependencies | None = None,
) -> APIRouter:
    deps = dependencies or GRCStudioDependencies()
    router = APIRouter(prefix="/compliance/grc-studio", tags=["no-code-grc-studio"])

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        enabled_probe = _dependency(request, "grc_studio_enabled_probe", deps.enabled_probe)
        readiness_probe = _dependency(request, "grc_studio_readiness_probe", deps.readiness_probe)
        store_factory = _dependency(request, "grc_studio_store_factory", deps.store_factory)
        try:
            feature_enabled = enabled_probe(tenant) if callable(enabled_probe) else _ops().enabled()
            configured = callable(store_factory) and callable(readiness_probe)
            ready = readiness_probe(tenant) if feature_enabled and configured else False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio readiness is unavailable"
            ) from exc
        if type(feature_enabled) is not bool or type(ready) is not bool:
            raise HTTPException(status_code=503, detail="GRC studio readiness is unavailable")
        return feature_enabled, configured, ready

    async def composition(request: Request):
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(probes, request, tenant)
        if not feature_enabled:
            raise HTTPException(status_code=403, detail="GRC studio is disabled")
        if not configured or ready is not True:
            raise HTTPException(
                status_code=503, detail="GRC studio operational readiness is not verified"
            )
        factory = _dependency(request, "grc_studio_store_factory", deps.store_factory)
        principal = _principal(request, tenant)
        try:
            store = await run_in_threadpool(
                factory,  # type: ignore[arg-type]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            valid = store.tenant_id == tenant and all(
                callable(getattr(store, name, None)) for name in _REQUIRED_STORE_METHODS
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio authority is unavailable"
            ) from exc
        if not valid:
            raise HTTPException(status_code=503, detail="GRC studio authority is unavailable")
        return _ops(), tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except HTTPException:
            raise
        except ops.GRCStudioNotFound as exc:
            raise HTTPException(
                status_code=404, detail="GRC studio resource was not found"
            ) from exc
        except ops.GRCStudioPermissionDenied as exc:
            raise HTTPException(
                status_code=403, detail="GRC studio action is not authorized"
            ) from exc
        except ops.GRCStudioConflict as exc:
            raise HTTPException(
                status_code=409, detail="GRC studio action conflicts with current state"
            ) from exc
        except ops.GRCStudioValidationError as exc:
            raise HTTPException(status_code=422, detail="GRC studio request is invalid") from exc
        except ops.GRCStudioIntegrityError as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio integrity verification failed"
            ) from exc
        except ops.GRCStudioConfigError as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio dependency is unavailable"
            ) from exc
        except ops.GRCStudioError as exc:
            raise HTTPException(status_code=503, detail="GRC studio operation failed") from exc
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio dependency operation failed"
            ) from exc

    async def runtime_dependencies(request: Request, tenant: str):
        resolver_factory = _dependency(
            request,
            "grc_studio_target_authority_resolver_factory",
            deps.target_authority_resolver_factory,
        )
        applier_factory = _dependency(
            request,
            "grc_studio_projection_applier_factory",
            deps.projection_applier_factory,
        )
        if not callable(resolver_factory):
            raise HTTPException(
                status_code=503, detail="GRC studio runtime target resolver is unavailable"
            )
        try:
            resolver = await run_in_threadpool(resolver_factory, tenant_id=tenant, request=request)
            applier = (
                await run_in_threadpool(applier_factory, tenant_id=tenant, request=request)
                if callable(applier_factory)
                else None
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="GRC studio runtime adapter is unavailable"
            ) from exc
        if not callable(resolver) or (callable(applier_factory) and not callable(applier)):
            raise HTTPException(status_code=503, detail="GRC studio runtime adapter is unavailable")
        return resolver, applier

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(probes, request, tenant)
        resolver = _dependency(
            request,
            "grc_studio_target_authority_resolver_factory",
            deps.target_authority_resolver_factory,
        )
        applier = _dependency(
            request, "grc_studio_projection_applier_factory", deps.projection_applier_factory
        )
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-studio-status.v1",
            "enabled": feature_enabled,
            "configured": configured,
            "ready": bool(feature_enabled and configured and ready),
            "runtime_projection_preview_configured": callable(resolver),
            "runtime_projection_apply_configured": callable(resolver) and callable(applier),
            "store_opened_for_status": False,
            "target_authority_resolved_for_status": False,
            "arbitrary_code_supported": False,
            "arbitrary_html_css_supported": False,
            "caller_urls_supported": False,
            "lifecycle": [
                "draft",
                "in_review",
                "reviewed",
                "approved",
                "published",
                "superseded",
                "rejected",
            ],
            "projection_kinds": ["questionnaire", "collector", "report"],
            "live_provider_acceptance_verified": False,
        }

    @router.get("")
    async def list_versions(
        request: Request,
        response: Response,
        studio_id: OpaqueId | None = Query(default=None),
        state: State | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1_000),
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        rows = await call(
            ops, store.list_versions, tenant, studio_id=studio_id, state=state, limit=limit
        )
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-version-list.v1",
            "count": len(rows),
            "items": _jsonable(rows),
        }

    @router.get("/sources")
    async def list_sources(request: Request, response: Response) -> dict[str, object]:
        """Current approved native evidence sources and listed destinations."""
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        from maverick.config import config_source_errors, load_config

        from . import grc_draft_changes as guarded

        context = guarded.authority(request)[2]
        if config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current evidence settings could not be read. Your entered work is kept.")
        cfg = load_config()
        parent = cfg.get("tech_risk_compliance") or {}
        if not isinstance(parent, Mapping) or not isinstance(parent.get("continuous_evidence") or {}, Mapping):
            raise HTTPException(503, "Current evidence settings could not be verified. Your entered work is kept.")
        evidence_enabled = parent.get("enable") is True and (parent.get("continuous_evidence") or {}).get("enable") is True
        collectors = await run_in_threadpool(_approved_collectors, request, tenant) if evidence_enabled else []
        targets: list[dict[str, object]] = []
        listed = False
        resolver_factory = _dependency(
            request,
            "grc_studio_target_authority_resolver_factory",
            deps.target_authority_resolver_factory,
        )
        if callable(resolver_factory):
            try:
                resolver = await run_in_threadpool(
                    resolver_factory, tenant_id=tenant, request=request
                )
                targets, listed = await run_in_threadpool(_listed_targets, resolver, tenant)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:  # noqa: BLE001 - a listing failure leaves the typed fallback
                targets, listed = [], False
        _secure(response)
        guarded.authority(request, context)
        return {
            "schema": "lightwork.no-code-grc-sources.v1",
            "context": context,
            "collectors": collectors,
            "collectors_notice": "Continuous evidence is turned off. Other blueprint choices remain available." if not evidence_enabled else "",
            "destinations": targets,
            "destinations_listed": listed,
        }

    @router.post("/studios/{studio_id}/versions")
    async def create_version(
        request: Request, response: Response, studio_id: ObjectPath, body: CreateVersionIn
    ) -> dict[str, object]:
        require_permission(request, "operate")
        from . import grc_draft_changes as guarded
        expected_context = guarded.context(request)
        ops, tenant, store = await composition(request)
        result = await call(
            ops, guarded.legacy_save, request, store, "create", tenant, studio_id, body.model_dump(mode="python"), expected_context
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.patch("/studios/{studio_id}/versions/{version}")
    async def replace_draft(
        request: Request,
        response: Response,
        studio_id: ObjectPath,
        version: int,
        body: ReplaceDraftIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        from . import grc_draft_changes as guarded
        expected_context = guarded.context(request)
        ops, tenant, store = await composition(request)
        result = await call(
            ops, guarded.legacy_save, request, store, "replace", tenant, studio_id, body.model_dump(mode="python"), expected_context, version=version
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/studios/{studio_id}/versions/{version}/submit")
    async def submit(
        request: Request,
        response: Response,
        studio_id: ObjectPath,
        version: int,
        body: VersionCASIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        result = await call(
            ops,
            store.submit_for_review,
            tenant,
            studio_id,
            version,
            **body.model_dump(mode="python"),
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/studios/{studio_id}/versions/{version}/review")
    async def review(
        request: Request, response: Response, studio_id: ObjectPath, version: int, body: ReviewIn
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(
            ops, store.review, tenant, studio_id, version, **body.model_dump(mode="python")
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/studios/{studio_id}/versions/{version}/approve")
    async def approve(
        request: Request, response: Response, studio_id: ObjectPath, version: int, body: ApproveIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(
            ops, store.approve, tenant, studio_id, version, **body.model_dump(mode="python")
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/studios/{studio_id}/versions/{version}/publish")
    async def publish(
        request: Request, response: Response, studio_id: ObjectPath, version: int, body: PublishIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(
            ops, store.publish, tenant, studio_id, version, **body.model_dump(mode="python")
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/studios/{studio_id}/rollback")
    async def rollback(
        request: Request, response: Response, studio_id: ObjectPath, body: RollbackIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(
            ops, store.rollback, tenant, studio_id, **body.model_dump(mode="python")
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/studios/{studio_id}/active")
    async def active(
        request: Request, response: Response, studio_id: ObjectPath
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        pointer, version = await call(ops, store.get_active, tenant, studio_id)
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-active-result.v1",
            "pointer": _jsonable(pointer),
            "version": _jsonable(version),
        }

    @router.get("/studios/{studio_id}/versions/{version}")
    async def get_version(
        request: Request, response: Response, studio_id: ObjectPath, version: int
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.get_version, tenant, studio_id, version)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/studios/{studio_id}/versions/{version}/history")
    async def history(
        request: Request, response: Response, studio_id: ObjectPath, version: int
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        rows = await call(ops, store.history, tenant, studio_id, version)
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-history.v1",
            "count": len(rows),
            "items": _jsonable(rows),
        }

    @router.post("/operations/export")
    async def export_version(
        request: Request, response: Response, body: ExportIn
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.export_version, tenant, **body.model_dump(mode="python"))
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/operations/import")
    async def import_version(
        request: Request, response: Response, body: ImportIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.import_version, tenant, **body.model_dump(mode="python"))
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/operations/projections/preview")
    async def preview_projection(
        request: Request, response: Response, body: ProjectionIn
    ) -> dict[str, object]:
        require_permission(request, "view")
        ops, tenant, store = await composition(request)
        resolver, _ = await runtime_dependencies(request, tenant)
        authority = await call(
            ops, resolver, tenant, body.projection_kind, body.target_id, body.target_revision
        )
        result = await call(
            ops,
            store.preview_projection,
            tenant,
            body.studio_id,
            projection_kind=body.projection_kind,
            definition_id=body.definition_id,
            target_authority=authority,
            expected_active_version=body.expected_active_version,
            expected_blueprint_sha256=body.expected_blueprint_sha256,
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/operations/projections/apply")
    async def apply_projection(
        request: Request, response: Response, body: ApplyProjectionIn
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        resolver, applier = await runtime_dependencies(request, tenant)
        if not callable(applier):
            raise HTTPException(status_code=503, detail="GRC studio runtime applier is unavailable")
        result = await call(
            ops,
            store.apply_projection,
            tenant,
            body.studio_id,
            **body.model_dump(mode="python", exclude={"studio_id"}),
            authority_resolver=resolver,
            applier=applier,
        )
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/operations/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.verify_integrity, tenant)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/operations/retention")
    async def retention(
        request: Request, response: Response, limit: int = Query(default=100, ge=1, le=1_000)
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        rows = await call(ops, store.retention_due, tenant, limit=limit)
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-retention-list.v1",
            "count": len(rows),
            "items": _jsonable(rows),
        }

    @router.post("/operations/retention/purge")
    async def purge(request: Request, response: Response, body: PurgeIn) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.purge_expired, tenant, limit=body.limit)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.post("/operations/recovery/backups")
    async def backup(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.create_recovery_backup, tenant)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    @router.get("/operations/recovery/backups")
    async def list_backups(
        request: Request, response: Response, limit: int = Query(default=50, ge=1, le=500)
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        lister = getattr(store, "list_recovery_backups", None)
        if not callable(lister):
            raise HTTPException(status_code=503, detail="GRC studio backup list is unavailable")
        rows = await call(ops, lister, tenant, limit=limit)
        _secure(response)
        return {
            "schema": "lightwork.no-code-grc-recovery-list.v1",
            "count": len(rows),
            "items": _jsonable(rows),
        }

    @router.get("/operations/recovery/backups/{backup_id}")
    async def verify_backup(
        request: Request, response: Response, backup_id: ObjectPath
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.verify_recovery_backup, tenant, backup_id)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    return router


router = create_no_code_grc_studio_router()

__all__ = [
    "GRCStudioDependencies",
    "create_no_code_grc_studio_router",
    "router",
]
