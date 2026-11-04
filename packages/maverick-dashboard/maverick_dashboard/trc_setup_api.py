"""Guided saved-account source setup and legacy configured-source controls.

Named account, scope and check choices become part of the existing native
definition's signed history. A different administrator approves the exact
setup before its separate enrollment starts collection. Legacy installation
manifests remain available without silently replacing their authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/compliance/continuous-evidence/setup", tags=["trc-setup"])

LOCAL_KEY = "local-soc2"
_PROVIDER_LABELS = {
    "aws_security_hub": "AWS Security Hub",
    "aws_config": "AWS Config",
    "azure_defender": "Microsoft Defender for Cloud",
    "azure_policy": "Azure Policy",
    "gcp_security_command_center": "Google Cloud Security Command Center",
    "github_security": "GitHub security alerts",
    "okta_posture": "Okta policies",
}


class EnrollIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    interval_seconds: int = Field(ge=3_600, le=366 * 24 * 3_600)
    retention_seconds: int = Field(ge=86_400, le=10 * 366 * 24 * 3_600)


def _sha(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _store(request: Request):
    from maverick import trc_continuous_evidence as evidence

    from . import trc_continuous_evidence_api as api

    try:
        evidence.require_enabled()
    except evidence.ContinuousEvidenceConfigError as exc:
        raise HTTPException(status_code=403, detail="Continuous evidence is turned off.") from exc
    tenant = api._tenant_id()
    principal = api._principal(request, tenant)
    factory = getattr(request.app.state, "trc_continuous_evidence_store_factory", None)
    try:
        if callable(factory):
            return evidence, tenant, factory(tenant_id=tenant, principal_ref=principal,
                                             principal_resolver=lambda: principal, request=request)
        return evidence, tenant, api._default_store_for(tenant, principal)
    except (evidence.ContinuousEvidenceError, OSError) as exc:
        raise HTTPException(status_code=503, detail="Continuous evidence is not available right now.") from exc


def _manifests(request: Request, tenant: str) -> dict[str, dict[str, Any]]:
    """Configured sources as {key: plan}; plans never reach the browser whole."""
    from maverick.trc_evidence_collectors import LocalSoc2Collector

    from . import trc_continuous_evidence_api as api

    allowed = api._collector_ids(request)
    plans: dict[str, dict[str, Any]] = {}
    if LocalSoc2Collector.collector_id in allowed:
        plans[LOCAL_KEY] = {
            "label": "Lightwork's own security checks",
            "definition_id": "local-soc2", "definition_version": 1,
            "collector_id": LocalSoc2Collector.collector_id, "collector_key_id": "local-soc2-key",
            "capability_revision": 1, "controls": sorted(LocalSoc2Collector._LOCAL_CONTROLS),
            "asset_scope_sha256": _sha({"schema": "lightwork.trc-local-asset-scope.v1", "tenant": tenant}),
            "credential_profile_sha256": _sha({"schema": "lightwork.trc-local-credential-profile.v1", "tenant": tenant}),
            "enrollment_id": "local-soc2", "credential_ready": True,
        }
    composition = getattr(request.app.state, "trc_stock_evidence_composition", None)
    settings = getattr(composition, "_settings", None)
    sources = ()
    if callable(settings):
        try:
            sources = settings(tenant).sources
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Current evidence source settings could not be read. Your work is kept; refresh after the connection is available.",
            ) from exc
    else:
        directory = getattr(composition, "directory", None)
        sources = tuple(getattr(directory, "_sources", {}).values()) if directory is not None else ()
    present = getattr(composition, "_credential_ref_present", None)
    for source in sources:
        if source.collector_id not in allowed:
            continue
        plans[source.enrollment_id] = {
            "label": _PROVIDER_LABELS.get(source.provider, source.provider.replace("_", " ").title()),
            "definition_id": source.definition_id, "definition_version": source.definition_version,
            "collector_id": source.collector_id, "collector_key_id": source.collector_key_id,
            "capability_revision": source.capability_revision,
            "controls": [item.control_ref for item in source.bindings],
            "asset_scope_sha256": source.asset_scope_sha256,
            "credential_profile_sha256": source.credential_profile_sha256,
            "enrollment_id": source.enrollment_id,
            "credential_ready": bool(present(source.credential_env)) if callable(present) else None,
            "managed": source.authorizing_principal is not None,
        }
        ready = getattr(composition, "_source_credential_ready", None)
        if callable(ready):
            plans[source.enrollment_id]["credential_ready"] = ready(source)
        if source.authorizing_principal is not None:
            definition = _store(request)[2].get_definition(source.definition_id, source.definition_version)
            plans[source.enrollment_id]["label"] = definition.source_manifest["label"]
            plans[source.enrollment_id]["state"] = definition.state
    return plans


def _plan(request: Request, tenant: str, key: str) -> dict[str, Any]:
    plan = _manifests(request, tenant).get(key)
    if plan is None:
        raise HTTPException(status_code=404, detail="That source is not configured for this workspace.")
    return plan


@router.get("")
async def configured_sources(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    _evidence, tenant, _store_value = _store(request)
    plans = await run_in_threadpool(_manifests, request, tenant)
    return {"items": [
        {"key": key, "label": plan["label"], "definition_id": plan["definition_id"],
         "definition_version": plan["definition_version"], "enrollment_id": plan["enrollment_id"],
         "control_count": len(plan["controls"]), "credential_ready": plan["credential_ready"],
         "managed": plan.get("managed", False), "editable": plan.get("managed", False),
         "state": plan.get("state")}
        for key, plan in plans.items()
    ]}


@router.post("/{key}/definition")
async def register_definition(request: Request, key: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    evidence, tenant, store = _store(request)
    plan = _plan(request, tenant, key)

    def write():
        if plan.get("managed"):
            return store.get_definition(plan["definition_id"], plan["definition_version"])
        return store.register_definition(
            definition_id=plan["definition_id"], version=plan["definition_version"],
            collector_id=plan["collector_id"], collector_schema_version=1,
            collector_key_id=plan["collector_key_id"], capability_revision=plan["capability_revision"],
            allowed_control_refs=plan["controls"],
        )

    try:
        await run_in_threadpool(write)
    except evidence.ContinuousEvidenceConflict as exc:
        raise HTTPException(status_code=409, detail="This source is already set up.") from exc
    except evidence.ContinuousEvidenceError as exc:
        raise HTTPException(status_code=422, detail="This source's settings could not be used.") from exc
    return {"registered": True}


@router.post("/{key}/enrollment")
async def enroll(request: Request, key: str, body: EnrollIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    evidence, tenant, store = _store(request)
    plan = _plan(request, tenant, key)

    def write():
        definition = store.get_definition(plan["definition_id"], plan["definition_version"])
        return store.enroll(
            enrollment_id=plan["enrollment_id"], definition_id=plan["definition_id"],
            definition_version=plan["definition_version"],
            expected_definition_integrity_sha256=definition.integrity_sha256,
            asset_scope_sha256=plan["asset_scope_sha256"],
            credential_profile_sha256=plan["credential_profile_sha256"],
            control_refs=plan["controls"], interval_seconds=body.interval_seconds,
            operation_id=f"setup-{uuid.uuid4().hex}", retention_seconds=body.retention_seconds,
            before_effect=managed_definition_guard(request, definition),
        )

    try:
        await run_in_threadpool(write)
    except evidence.ContinuousEvidenceNotFound as exc:
        raise HTTPException(status_code=409, detail="Set up and approve the collection first.") from exc
    except (evidence.ContinuousEvidenceConflict, evidence.ContinuousEvidencePermissionDenied) as exc:
        raise HTTPException(status_code=409, detail="The collection must be approved before it can start.") from exc
    except evidence.ContinuousEvidenceError as exc:
        raise HTTPException(status_code=422, detail="This source's settings could not be used.") from exc
    return {"enrolled": True}


Provider = Literal["aws_security_hub", "aws_config", "azure_defender", "azure_policy",
                   "gcp_security_command_center", "github_security", "okta_posture"]


class SourceScope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    provider: Provider
    connection_name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    connection_revision: str = Field(pattern=r"^[0-9a-f]{32}$")
    scope_ref: str = Field(min_length=1, max_length=512)
    region: str | None = Field(default=None, max_length=64)
    stream: str | None = Field(default=None, max_length=64)


class SourceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    control_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    source_ref: str = Field(min_length=1, max_length=512)
    check_label: str | None = Field(default=None, min_length=1, max_length=200)
    control_label: str | None = Field(default=None, min_length=1, max_length=500)


class SourceDraft(SourceScope):
    label: str = Field(min_length=1, max_length=100)
    bindings: list[SourceBinding] = Field(min_length=1, max_length=250)
    background_authorized: Literal[True]
    definition_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.:-]{0,100}$")
    expected_version: int | None = Field(default=None, ge=1, le=2**31-2)
    expected_integrity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class SourceContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: str
    principal_ref: str
    workspace_generation: int = Field(ge=0)
    workspace_authority: Literal["principal_selection", "principal_isolation", "operator_floor"]


class SourceSave(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    draft: SourceDraft
    context: SourceContext
    operation_id: str = Field(pattern=r"^source-[0-9a-f]{32}$")
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: int = Field(ge=0)


def _source_access(request: Request, *, historical: bool = False, allow_unnamed: bool = False):
    from maverick import trc_continuous_evidence as evidence

    from . import auth, workspace_tenants
    from . import trc_continuous_evidence_api as api
    from ._shared import authenticated_subject
    from .app import require_page_visible

    require_global_permission(request, "admin")
    auth.require_page_permission(request, "/compliance/continuous-evidence")
    require_page_visible(request, "/compliance/continuous-evidence")
    if not historical and not auth.suite_allowed(request, "it_grc"):
        raise HTTPException(403, "Your current department access does not permit technology control evidence setup.")
    tenant = api._tenant_id()
    owner = authenticated_subject(request, error_detail="Sign in to choose a saved evidence account.")
    if not auth.caller_principal(request) and not allow_unnamed:
        raise HTTPException(403, "Sign in with a named administrator account before choosing a saved account for background evidence collection.")
    generation = 0
    mode = getattr(request.state, "workspace_tenant_source", None) or "operator_floor"
    if mode == "principal_selection":
        selected, generation = workspace_tenants.get_selection_binding(owner)
        if selected != tenant or not workspace_tenants.principal_can_select(owner, tenant):
            raise HTTPException(409, "Your workspace changed. Read the current source setup again.")
    context = {"tenant_id": tenant, "principal_ref": owner, "workspace_generation": generation,
               "workspace_authority": mode}
    if not historical:
        from .trc_stock_evidence_composition import source_workspace_authorized

        if not source_workspace_authorized(tenant, owner, mode):
            raise HTTPException(409, "Select an active workspace that permits this account before setting up background evidence collection.")
        try:
            evidence.require_enabled()
        except evidence.ContinuousEvidenceConfigError as exc:
            raise HTTPException(403, "Continuous evidence is turned off. The original saved setup can still be read.") from exc
    return evidence, tenant, owner, context


def _source_store(request: Request, *, historical: bool = False):
    evidence, tenant, owner, context = _source_access(request, historical=historical)
    if not historical:
        return evidence, _store(request)[2], owner, context
    from maverick.paths import data_dir

    from . import trc_continuous_evidence_api as api

    path = data_dir("tech_risk_compliance", "continuous-evidence.sqlite3", tenant=tenant)
    if not path.is_file():
        return evidence, None, owner, context
    store = evidence.ContinuousEvidenceStore(path, tenant_id=tenant,
        principal_resolver=lambda: api._principal(request, tenant), config_gate=lambda: None)
    return evidence, store, owner, context


def _source_controls() -> dict[str, str]:
    from maverick import security_ops

    controls = {row["id"]: row["title"] for row in security_ops.CONTROL_CATALOG}
    if security_ops.enabled():
        for row in security_ops.list_controls():
            identifier = row.get("control_id") or row.get("id")
            if isinstance(identifier, str) and len(identifier) <= 128:
                controls.setdefault(identifier, str(row.get("title") or "Saved control"))
    return controls


def _draft_source(tenant, owner, body: SourceScope, *, workspace_authority, bindings=None):
    from maverick import connections
    from maverick.trc_stock_evidence_collectors import ProviderControlBinding, StockCollectorSource

    rows = connections.list_connections() if connections.enabled() else []
    record = next((row for row in rows if row["name"] == body.connection_name), None)
    admitted = {body.provider, "github"} if body.provider == "github_security" else {body.provider}
    if (not record or record.get("revision") != body.connection_revision or not record.get("has_token") or
            record.get("connector") not in admitted or not connections._may_use(record, owner)):
        raise HTTPException(409, "That saved account changed or is unavailable. Select its current saved version.")
    source = StockCollectorSource(tenant_id=tenant, enrollment_id="source-review", definition_id="source-review",
        definition_version=1, definition_integrity_sha256="0" * 64, collector_key_id="source-review-key",
        capability_revision=1, provider=body.provider, origin=record["base_url"].rstrip("/"),
        scope_ref=body.scope_ref, region=body.region, stream=body.stream,
        credential_env=f"connection:{body.connection_name}:{body.connection_revision}",
        authorizing_principal=owner,
        workspace_authority=workspace_authority,
        bindings=tuple(ProviderControlBinding(control_ref=item.control_ref, source_ref=item.source_ref)
                       for item in bindings) if bindings else (ProviderControlBinding("setup-review", "setup-review"),))
    return source


def _source_manifest(source, draft: SourceDraft) -> dict:
    return {"label": draft.label.strip(), "provider": source.provider, "origin": source.origin,
            "scope_ref": source.scope_ref, "region": source.region, "stream": source.stream,
            "credential_env": source.credential_env, "authorizing_principal": source.authorizing_principal,
            "background_authorized": True,
            "workspace_authority": source.workspace_authority,
            "bindings": [{"control_ref": item.control_ref, "source_ref": item.source_ref} for item in source.bindings],
            "check_labels": {item.source_ref: item.check_label or item.source_ref for item in draft.bindings},
            "control_labels": {item.control_ref: item.control_label or item.control_ref for item in draft.bindings}}


def _source_summary(manifest: dict) -> dict:
    controls = manifest.get("control_labels", {})
    _, account, _revision = manifest["credential_env"].split(":")
    return {"label": manifest["label"], "provider": _PROVIDER_LABELS[manifest["provider"]],
            "account": account, "scope": manifest["scope_ref"], "region": manifest["region"],
            "stream": manifest["stream"],
            "controls": [{"control": controls.get(item["control_ref"], "Previously saved control: " + item["control_ref"]),
                          "check": manifest.get("check_labels", {}).get(item["source_ref"], item["source_ref"])}
                         for item in manifest["bindings"]],
            "background_authorization": "Use this exact saved account for these read-only checks while your current access remains valid.",
            "change_effect": "Save a pending setup. Changes pause the previous active collection and cancel its waiting work. Another administrator must approve this version; Start collecting is a separate action."}


def _review_signature(tenant: str, envelope: dict) -> str:
    from maverick.tenant.kms import tenant_dek

    key = hmac.digest(tenant_dek(tenant), b"lightwork.trc-source-review.v1", "sha256")
    return hmac.new(key, json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(), "sha256").hexdigest()


def _source_result(definition, *, replayed=False, paused_enrollments=0):
    return {"saved": True, "definition_id": definition.definition_id, "version": definition.version,
            "state": "pending", "paused_enrollments": paused_enrollments, "replayed": replayed,
            "summary": _source_summary(definition.source_manifest)}


def managed_definition_guard(request: Request, definition):
    """Recheck the same native managed source after writer waits and before commit."""
    if definition.source_manifest is None:
        return None
    from maverick.trc_stock_evidence_collectors import managed_source_from_definition

    from .trc_stock_evidence_composition import source_account_metadata, source_owner_authorized

    _evidence, tenant, _owner, context = _source_access(request)
    source = managed_source_from_definition(tenant, definition)
    def check():
        if _source_access(request)[3] != context:
            raise HTTPException(409, "Your workspace or account changed. Review the current source setup again.")
        source_owner_authorized(tenant, source.authorizing_principal, source.workspace_authority)
        source_account_metadata(source)
        from .trc_stock_evidence_composition import stock_collector_settings

        composition = getattr(request.app.state, "trc_stock_evidence_composition", None)
        settings = stock_collector_settings(composition._config_loader(tenant), tenant_id=tenant)
        if not settings.stock_enabled or source.collector_id not in settings.enabled_collector_ids:
            raise HTTPException(403, "This evidence provider is turned off in Settings.")
    def guard():
        try:
            check()
        except Exception as exc:
            raise _source_error(exc) from exc
    return guard


def _source_error(exc):
    from maverick import connections
    from maverick import trc_continuous_evidence as evidence
    from maverick.trc_stock_evidence_collectors import (
        StockEvidenceAccessDenied,
        StockEvidenceConfigurationError,
        StockEvidenceProtocolError,
        StockEvidenceUnavailable,
    )

    from .auth import AutomationAuthorizationError

    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (evidence.ContinuousEvidenceConflict, connections.ConnectionVersionConflict)):
        return HTTPException(409, "The source or saved account changed. Read and review its current setup.")
    if isinstance(exc, (StockEvidenceAccessDenied, evidence.ContinuousEvidencePermissionDenied, PermissionError, AutomationAuthorizationError)):
        return HTTPException(403, "Current access does not permit that source. Review your saved account and permissions.")
    if isinstance(exc, (StockEvidenceConfigurationError, evidence.ContinuousEvidenceValidationError, ValueError)):
        return HTTPException(422, "Check the account, scope and selected checks. Every selected check must have one distinct control.")
    if isinstance(exc, StockEvidenceProtocolError):
        return HTTPException(502, "The provider's available checks could not be read safely. No setup or collection was started.")
    if isinstance(exc, StockEvidenceUnavailable):
        return HTTPException(504, "The provider is unavailable right now. Your choices are kept; no setup or collection was started.")
    return HTTPException(503, "Source setup could not be verified right now. Your work is kept; read the original save if a save was attempted.")


@router.get("/source-options")
async def source_options(request: Request):
    def read():
        from maverick import connections

        from . import auth

        evidence, _tenant, owner, context = _source_access(request, allow_unnamed=True)
        store = _store(request)[2]
        composition = getattr(request.app.state, "trc_stock_evidence_composition", None)
        settings = composition._settings(context["tenant_id"])
        if not settings.stock_enabled or not auth.caller_principal(request):
            return {"providers": [], "controls": [], "sources": [], "context": context,
                    "connections_url": "/connections", "setup_available": False,
                    "notice": ("Turn on external evidence collection in Settings first." if not settings.stock_enabled else
                               "Sign in with a named administrator account before choosing a saved account for background evidence collection.")}
        rows = connections.list_connections() if connections.enabled() else []
        providers = []
        for provider, label in _PROVIDER_LABELS.items():
            from maverick.trc_stock_evidence_collectors import _PROVIDER_TO_COLLECTOR

            if _PROVIDER_TO_COLLECTOR[provider] not in settings.enabled_collector_ids:
                continue
            accounts = [{"name": row["name"], "label": row["name"], "revision": row["revision"]}
                        for row in rows if row["connector"] in ({provider, "github"} if provider == "github_security" else {provider})
                        and row.get("has_token") and connections._may_use(row, owner)]
            streams = ({"code_scanning": "Code security", "dependabot": "Dependency security", "secret_scanning": "Exposed secrets"}  # pragma: allowlist secret -- display labels, not a value
                       if provider == "github_security" else
                       {"ACCESS_POLICY": "Access policies", "IDP_DISCOVERY": "Identity provider discovery",
                        "MFA_ENROLL": "Authentication enrollment", "OKTA_SIGN_ON": "Sign-in policies", "PASSWORD": "Password policies"}  # pragma: allowlist secret -- display labels, not a value
                       if provider == "okta_posture" else {})
            providers.append({"id": provider, "label": label, "accounts": accounts,
                "scope_label": ("AWS account number" if provider.startswith("aws_") else
                                "Azure subscription" if provider.startswith("azure_") else
                                "Google Cloud organization, folder or project" if provider.startswith("gcp_") else
                                "GitHub organization or organization/repository" if provider == "github_security" else "Okta organization name"),
                "region_required": provider.startswith("aws_"), "max_bindings": 25 if provider == "aws_config" else 250,
                "streams": [{"id": key, "label": value} for key, value in streams.items()]})
        sources = []
        for definition in store.list_source_definitions():
            manifest = definition.source_manifest
            _, name, revision = manifest["credential_env"].split(":")
            sources.append({"definition_id": definition.definition_id, "version": definition.version,
                "expected_version": definition.version, "expected_integrity_sha256": definition.integrity_sha256,
                "state": definition.state, "managed": True, "editable": True, "label": manifest["label"],
                "provider": manifest["provider"], "connection_name": name, "connection_revision": revision,
                "scope_ref": manifest["scope_ref"], "region": manifest["region"], "stream": manifest["stream"],
                "bindings": [{**item, "check_label": manifest.get("check_labels", {}).get(item["source_ref"]),
                              "control_label": manifest.get("control_labels", {}).get(item["control_ref"])} for item in manifest["bindings"]],
                "background_authorized": True, "summary": _source_summary(manifest)})
        if _source_access(request)[3] != context:
            raise HTTPException(409, "Your workspace or access changed. Read the current source setup again.")
        return {"providers": providers, "setup_available": True, "controls": [{"id": key, "label": value} for key, value in _source_controls().items()],
                "sources": sources, "context": context, "connections_url": "/connections",
                "notice": "Sources saved here use their approved saved-account version. Installation-managed sources remain separately available and cannot be silently replaced."}
    try:
        return await run_in_threadpool(read)
    except Exception as exc:
        raise _source_error(exc) from exc


def _checks(request, body: SourceScope):
    from maverick.trc_stock_evidence_collectors import (
        PinnedStockEvidenceHTTPTransport,
        available_source_checks,
    )

    from .trc_stock_evidence_composition import source_account_credential, source_account_metadata

    _evidence, tenant, owner, context = _source_access(request)
    source = _draft_source(tenant, owner, body, workspace_authority=context["workspace_authority"])
    composition = getattr(request.app.state, "trc_stock_evidence_composition", None)
    settings = composition._settings(tenant)
    if not settings.stock_enabled or source.collector_id not in settings.enabled_collector_ids:
        raise HTTPException(403, "This evidence provider is turned off in Settings.")
    def authorize(_call):
        if _source_access(request)[3] != context:
            raise HTTPException(409, "Your workspace changed. Read the source setup again.")
        source_account_metadata(source)
    factory = getattr(request.app.state, "trc_source_setup_transport_factory", None)
    transport = factory(source, authorize) if callable(factory) else PinnedStockEvidenceHTTPTransport(
        authorize=authorize, request_credential_resolver=source_account_credential)
    authorize(None)
    result = available_source_checks(source, transport)
    authorize(None)
    return result


@router.post("/source-checks")
async def source_checks(request: Request, body: SourceScope):
    try:
        return await run_in_threadpool(_checks, request, body)
    except Exception as exc:
        raise _source_error(exc) from exc


@router.post("/sources/review")
async def source_review(request: Request, body: SourceDraft):
    def review():
        _evidence, store, owner, context = _source_store(request)
        controls = _source_controls()
        available = {item["id"]: item["label"] for item in _checks(request, SourceScope(**body.model_dump(include=set(SourceScope.model_fields))))["items"]}
        bindings = []
        for item in body.bindings:
            if item.control_ref not in controls or item.source_ref not in available:
                raise HTTPException(409, "A selected check or control is not in the current available choices. Read the choices again.")
            bindings.append(item.model_copy(update={"check_label": available[item.source_ref],
                                                    "control_label": controls[item.control_ref]}))
        draft = body.model_copy(update={"label": body.label.strip(), "bindings": bindings})
        source = _draft_source(context["tenant_id"], owner, draft, bindings=bindings,
                               workspace_authority=context["workspace_authority"])
        if draft.definition_id is not None:
            previous = store.get_definition(draft.definition_id, draft.expected_version or 0)
            if previous.source_manifest is None or previous.integrity_sha256 != draft.expected_integrity_sha256:
                raise HTTPException(409, "That source changed. Read its current setup again.")
        elif draft.expected_version is not None or draft.expected_integrity_sha256 is not None:
            raise HTTPException(422, "Choose a current saved source before changing its setup.")
        envelope = {"draft": draft.model_dump(), "context": context, "operation_id": "source-" + uuid.uuid4().hex,
                    "expires_at": int(time.time()) + 300}
        envelope["review_sha256"] = _review_signature(context["tenant_id"], envelope)
        return {**envelope, "summary": _source_summary(_source_manifest(source, draft))}
    try:
        return await run_in_threadpool(review)
    except Exception as exc:
        raise _source_error(exc) from exc


def _saved_request(request, body: SourceSave, *, historical=False):
    evidence, store, owner, context = _source_store(request, historical=historical)
    expected_context = body.context.model_dump()
    matches = (context["tenant_id"] == expected_context["tenant_id"] and
               context["principal_ref"] == expected_context["principal_ref"]) if historical else context == expected_context
    if not matches:
        raise HTTPException(409, "Your workspace or account changed. Read the original from the same workspace and account.")
    draft = body.draft
    if historical:
        # Origin is recovered only from the original native request's saved source
        # record below, never from the current rotated/deleted connection.
        definition_id = draft.definition_id or "source-" + hashlib.sha256((context["tenant_id"] + ":" + body.operation_id).encode()).hexdigest()[:40]
        version = draft.expected_version + 1 if draft.expected_version is not None else 1
        if store is None:
            return None
        try:
            definition = store.get_definition(definition_id, version)
        except evidence.ContinuousEvidenceNotFound:
            return None
        manifest = dict(definition.source_manifest or {})
        manifest.update(label=draft.label.strip(), scope_ref=draft.scope_ref, region=draft.region,
                        stream=draft.stream, provider=draft.provider, authorizing_principal=owner,
                        credential_env=f"connection:{draft.connection_name}:{draft.connection_revision}",
                        background_authorized=True,
                        bindings=[{"control_ref": item.control_ref, "source_ref": item.source_ref} for item in sorted(draft.bindings, key=lambda item: item.control_ref)],
                        check_labels={item.source_ref: item.check_label or item.source_ref for item in draft.bindings})
        if "control_labels" in manifest or any(item.control_label is not None for item in draft.bindings):
            manifest["control_labels"] = {item.control_ref: item.control_label or item.control_ref for item in draft.bindings}
        original = store.source_original(operation_id=body.operation_id, definition_id=definition_id, version=version,
                                        source_manifest=manifest, expected_previous_integrity_sha256=draft.expected_integrity_sha256)
        return (original, store.source_pause_count(original)) if original is not None else None
    if not time.time() <= body.expires_at <= time.time() + 300:
        raise HTTPException(409, "This review expired. Review the complete source setup again before saving.")
    envelope = body.model_dump(exclude={"review_sha256"})
    if not hmac.compare_digest(body.review_sha256, _review_signature(context["tenant_id"], envelope)):
        raise HTTPException(409, "The reviewed choices changed. Review the complete source setup again.")
    source = _draft_source(context["tenant_id"], owner, draft, bindings=draft.bindings,
                           workspace_authority=context["workspace_authority"])
    composition = getattr(request.app.state, "trc_stock_evidence_composition", None)
    settings = composition._settings(context["tenant_id"])
    if not settings.stock_enabled or source.collector_id not in settings.enabled_collector_ids:
        raise HTTPException(403, "This evidence provider is turned off in Settings.")
    definition_id = draft.definition_id or "source-" + hashlib.sha256((context["tenant_id"] + ":" + body.operation_id).encode()).hexdigest()[:40]
    version = draft.expected_version + 1 if draft.expected_version is not None else 1
    def admit():
        from .trc_stock_evidence_composition import (
            source_account_metadata,
            stock_collector_settings,
        )

        if _source_access(request)[3] != context or time.time() > body.expires_at:
            raise HTTPException(409, "This source review expired or its workspace changed. Review it again before saving.")
        source_account_metadata(source)
        current_settings = stock_collector_settings(composition._config_loader(context["tenant_id"]), tenant_id=context["tenant_id"])
        if not current_settings.stock_enabled or source.collector_id not in current_settings.enabled_collector_ids:
            raise HTTPException(403, "This evidence provider is turned off in Settings.")
        controls = _source_controls()
        if any(controls.get(item.control_ref) != item.control_label for item in draft.bindings):
            raise HTTPException(409, "A selected control changed. Review the current choices again.")
    definition = store.register_definition(definition_id=definition_id, version=version,
        collector_id=source.collector_id, collector_schema_version=1, collector_key_id=definition_id + ".key",
        capability_revision=version, allowed_control_refs=[item.control_ref for item in source.bindings],
        source_manifest=_source_manifest(source, draft), expected_previous_integrity_sha256=draft.expected_integrity_sha256,
        operation_id=body.operation_id, before_effect=admit)
    return definition, store.source_pause_count(definition)


@router.post("/sources/save")
async def source_save(request: Request, body: SourceSave):
    def write():
        from maverick import connections
        from maverick.authority_effects import authority_effect_fence

        with authority_effect_fence(), connections._mutation_lock():
            return _saved_request(request, body)
    try:
        definition, paused = await run_in_threadpool(write)
        _source_access(request)
        return _source_result(definition, paused_enrollments=paused)
    except Exception as exc:
        raise _source_error(exc) from exc


@router.post("/sources/original")
async def source_original(request: Request, body: SourceSave):
    try:
        original = await run_in_threadpool(_saved_request, request, body, historical=True)
        _source_access(request, historical=True)
        return {"found": original is not None, "result": _source_result(original[0], replayed=True, paused_enrollments=original[1]) if original is not None else None}
    except Exception as exc:
        raise _source_error(exc) from exc
