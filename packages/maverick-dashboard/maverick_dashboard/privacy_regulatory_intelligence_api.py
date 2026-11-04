"""Tenant-bound API for licensed, evidence-grounded privacy research."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST = r"^[0-9a-f]{64}$"
_JURISDICTION = r"^[A-Z][A-Z0-9-]{1,31}$"
_LANGUAGE = r"^[a-z]{2,3}(?:-[A-Z]{2})?$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID),
]
ObjectPath = Annotated[str, ApiPath(min_length=1, max_length=128, pattern=_ID)]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST),
]
Jurisdiction = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=2,
        max_length=32,
        pattern=_JURISDICTION,
    ),
]
Language = Annotated[
    str,
    StringConstraints(strict=True, min_length=2, max_length=6, pattern=_LANGUAGE),
]

AllowedUse = Literal["search", "research", "compare", "alerts", "reports", "share"]
DocumentType = Literal[
    "authority_guidance",
    "case_law",
    "enforcement_action",
    "law",
    "regulation",
    "regulatory_update",
    "standard",
]
CollectionRole = Literal["viewer", "editor", "owner"]
ShareScope = Literal["view", "export"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SourceIn(_StrictModel):
    name: str = Field(min_length=1, max_length=500)
    license_ref: str = Field(min_length=1, max_length=500)
    rights_basis: str = Field(min_length=1, max_length=2_000)
    allowed_uses: list[AllowedUse] = Field(min_length=1, max_length=6)
    provenance_uri: str = Field(min_length=1, max_length=2_048)
    jurisdictions: list[Jurisdiction] = Field(min_length=1, max_length=100)
    authorities: list[OpaqueId] = Field(min_length=1, max_length=100)
    document_types: list[DocumentType] = Field(min_length=1, max_length=7)
    languages: list[Language] = Field(min_length=1, max_length=100)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class SourceReviewIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    rationale: str = Field(min_length=1, max_length=2_000)
    approved: bool
    idempotency_key: IdempotencyKey


class SourceRevokeIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    reason: str = Field(min_length=1, max_length=2_000)
    idempotency_key: IdempotencyKey


class CitationIn(_StrictModel):
    citation_id: OpaqueId
    title: str = Field(min_length=1, max_length=500)
    uri: str = Field(min_length=1, max_length=2_048)
    pinpoint: str = Field(min_length=1, max_length=500)


class DocumentIn(_StrictModel):
    source_id: OpaqueId
    title: str = Field(min_length=1, max_length=1_000)
    jurisdiction: Jurisdiction
    authority: OpaqueId
    document_type: DocumentType
    language: Language
    publication_date: str = Field(min_length=10, max_length=10)
    effective_date: str | None = Field(default=None, min_length=10, max_length=10)
    superseded_date: str | None = Field(default=None, min_length=10, max_length=10)
    citations: list[CitationIn] = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=524_288)
    content_sha256: Digest
    expected_latest_version: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class SearchIn(_StrictModel):
    query: str = Field(min_length=1, max_length=2_048)
    jurisdictions: list[Jurisdiction] | None = Field(default=None, max_length=100)
    limit: int = Field(default=20, ge=1, le=100)
    as_of: str | None = Field(default=None, min_length=10, max_length=10)


class ResearchIn(SearchIn):
    minimum_evidence: int = Field(default=1, ge=1, le=100)


class CompareIn(_StrictModel):
    query: str = Field(min_length=1, max_length=2_048)
    jurisdictions: list[Jurisdiction] = Field(min_length=2, max_length=100)
    minimum_evidence_per_jurisdiction: int = Field(default=1, ge=1, le=100)
    as_of: str | None = Field(default=None, min_length=10, max_length=10)


class CollectionIn(_StrictModel):
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=2_000)
    jurisdictions: list[Jurisdiction] = Field(min_length=1, max_length=100)
    idempotency_key: IdempotencyKey


class CollectionGrantIn(_StrictModel):
    principal_ref: OpaqueId
    role: CollectionRole
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class CollectionDocumentIn(_StrictModel):
    document_id: OpaqueId
    version: int = Field(ge=1, le=2**31 - 1)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ShareIn(_StrictModel):
    scopes: list[ShareScope] = Field(min_length=1, max_length=2)
    expires_at: float = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class RedeemShareIn(_StrictModel):
    token: str = Field(min_length=32, max_length=512)
    scope: ShareScope = "view"


class SubscriptionIn(_StrictModel):
    query: str = Field(min_length=1, max_length=2_048)
    jurisdictions: list[Jurisdiction] = Field(min_length=1, max_length=100)
    destination_ref: OpaqueId
    cadence_seconds: int = Field(ge=300, le=31_536_000)
    expected_revision: int = Field(default=0, ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class GenerateAlertsIn(_StrictModel):
    version: int = Field(ge=1, le=2**31 - 1)


class ClaimDeliveriesIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: float = Field(default=60.0, ge=1.0, le=3_600.0)


class RunDeliveriesIn(ClaimDeliveriesIn):
    base_backoff_seconds: float = Field(default=30.0, ge=1.0, le=86_400.0)
    maximum_backoff_seconds: float = Field(
        default=86_400.0,
        ge=1.0,
        le=2_592_000.0,
    )


class FailDeliveryIn(_StrictModel):
    lease_token: str = Field(min_length=16, max_length=512)
    error_code: OpaqueId
    backoff_seconds: float = Field(ge=1.0, le=604_800.0)


class AcknowledgeDeliveryIn(_StrictModel):
    lease_token: str = Field(min_length=16, max_length=512)


class ReportIn(_StrictModel):
    query: str = Field(min_length=1, max_length=2_048)
    jurisdictions: list[Jurisdiction] = Field(min_length=1, max_length=100)
    retention_seconds: int = Field(ge=86_400, le=315_360_000)
    idempotency_key: IdempotencyKey


def _ops():
    from maverick import privacy_regulatory_intelligence as ops

    try:
        ops.require_enabled()
    except ops.PrivacyRegulatoryIntelligenceConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using privacy intelligence",
        )
    return tenant


def _principal(request: Request, tenant_id: str, purpose: str) -> str:
    principal = getattr(request.state, "principal", None)
    subject = str(getattr(principal, "sub", None) or "local-operator")
    # Identity must remain stable across duties.  Including ``purpose`` in the
    # digest would let one authenticated subject appear as both preparer and
    # reviewer, silently defeating the core authority's four-eyes check.
    del purpose
    digest = hashlib.sha256(
        (
            "lightwork.privacy-regulatory-intelligence.identity.v1:"
            f"{tenant_id}:{subject}"
        ).encode()
    ).hexdigest()
    return f"pri-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(tenant_id: str):
    from maverick.paths import data_dir
    from maverick.privacy_regulatory_intelligence import (
        PrivacyRegulatoryIntelligenceStore,
    )

    return PrivacyRegulatoryIntelligenceStore(
        data_dir(
            "privacy_automation",
            "privacy-regulatory-intelligence.sqlite3",
            tenant=tenant_id,
        )
    )


class PrivacyIntelligenceDependencies:
    def __init__(self, *, store_for: Callable[[str], Any] = _default_store_for) -> None:
        self.store_for = store_for


def create_privacy_intelligence_router(  # noqa: C901 - explicit route assembly
    dependencies: PrivacyIntelligenceDependencies | None = None,
) -> APIRouter:
    deps = dependencies or PrivacyIntelligenceDependencies()
    router = APIRouter(
        prefix="/privacy/regulatory-intelligence",
        tags=["privacy-regulatory-intelligence"],
    )

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        return ops, tenant, deps.store_for(tenant)

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.PrivacyRegulatoryIntelligenceNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligencePermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligenceConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligenceValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligenceIntegrityError as exc:
            raise HTTPException(
                status_code=500,
                detail="privacy intelligence integrity verification failed",
            ) from exc
        except ops.PrivacyRegulatoryIntelligenceConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligenceError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy intelligence operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        _ops()
        from maverick import mailer

        return {
            "schema": "lightwork.privacy-regulatory-intelligence-status.v1",
            "enabled": True,
            "licensed_corpus_bundled": False,
            "corpus_grounded_only": True,
            "legal_advice": False,
            "live_source_acceptance_verified": False,
            "delivery_destination_resolver_configured": callable(
                getattr(
                    request.app.state,
                    "privacy_intelligence_destination_resolver",
                    None,
                )
            ),
            "smtp_sender_configured": mailer.configured(),
        }

    @router.get("/records")
    async def records(request: Request) -> dict[str, Any]:
        """Latest document versions, saved trackers and evidence reports for
        the page lists (no document text, no delivery lease tokens)."""

        require_permission(request, "view")
        ops, tenant, store = authority(request)
        listed = await call(ops, store.list_records, tenant)
        return {
            "documents": [
                {
                    "document_id": d.document_id,
                    "version": d.version,
                    "source_id": d.source_id,
                    "title": d.title,
                    "jurisdiction": d.jurisdiction,
                    "authority": d.authority,
                    "document_type": d.document_type,
                    "language": d.language,
                    "publication_date": d.publication_date,
                    "effective_date": d.effective_date,
                    "ingested_at": d.ingested_at,
                }
                for d in listed["documents"]
            ],
            "trackers": [
                {
                    "subscription_id": q.subscription_id,
                    "query": q.query,
                    "jurisdictions": list(q.jurisdictions),
                    "destination_ref": q.destination_ref,
                    "cadence_seconds": q.cadence_seconds,
                    "next_run_at": q.next_run_at,
                    "state": q.state,
                    "revision": q.revision,
                }
                for q in listed["subscriptions"]
            ],
            "reports": [
                {
                    "report_id": r.report_id,
                    "query": r.query,
                    "jurisdictions": list(r.jurisdictions),
                    "status": r.status,
                    "evidence": len(r.evidence),
                    "created_at": r.created_at,
                }
                for r in listed["reports"]
            ],
        }

    @router.put("/sources/{source_id}")
    async def enroll_source(
        request: Request,
        source_id: ObjectPath,
        body: SourceIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        result = await call(
            ops,
            store.enroll_source,
            tenant,
            source_id=source_id,
            actor_ref=_principal(request, tenant, "actor"),
            **body.model_dump(),
        )
        return _jsonable(result)

    @router.get("/sources")
    async def list_sources(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.list_sources, tenant)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.get("/sources/{source_id}")
    async def source_detail(request: Request, source_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(await call(ops, store.get_source, tenant, source_id))

    @router.post("/sources/{source_id}/review")
    async def review_source(
        request: Request,
        source_id: ObjectPath,
        body: SourceReviewIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.approve_source,
                tenant,
                source_id,
                approver_ref=_principal(request, tenant, "reviewer"),
                **body.model_dump(),
            )
        )

    @router.post("/sources/{source_id}/revoke")
    async def revoke_source(
        request: Request,
        source_id: ObjectPath,
        body: SourceRevokeIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_source,
                tenant,
                source_id,
                actor_ref=_principal(request, tenant, "actor"),
                **body.model_dump(),
            )
        )

    @router.put("/documents/{document_id}")
    async def ingest_document(
        request: Request,
        document_id: ObjectPath,
        body: DocumentIn,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        payload = body.model_dump()
        payload["citations"] = [item.model_dump() for item in body.citations]
        result = await call(
            ops,
            store.ingest_document,
            tenant,
            document_id=document_id,
            actor_ref=_principal(request, tenant, "actor"),
            **payload,
        )
        return _jsonable(result)

    @router.get("/documents/{document_id}")
    async def document_detail(
        request: Request,
        document_id: ObjectPath,
        version: int | None = Query(default=None, ge=1, le=2**31 - 1),
    ) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(ops, store.get_document, tenant, document_id, version)
        )

    @router.get("/documents/{document_id}/versions")
    async def document_versions(
        request: Request,
        document_id: ObjectPath,
    ) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.list_document_versions, tenant, document_id)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/search")
    async def search(request: Request, body: SearchIn) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.search, tenant, **body.model_dump())
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/research")
    async def research(request: Request, body: ResearchIn) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        answer = await call(ops, store.research, tenant, **body.model_dump())
        payload = _jsonable(answer)
        payload["abstained"] = answer.status != "grounded"
        payload["legal_advice"] = False
        return payload

    @router.post("/compare")
    async def compare(request: Request, body: CompareIn) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.compare_jurisdictions,
                tenant,
                **body.model_dump(),
            )
        )

    @router.put("/collections/{collection_id}")
    async def create_collection(
        request: Request,
        collection_id: ObjectPath,
        body: CollectionIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.create_collection,
                tenant,
                collection_id=collection_id,
                owner_ref=_principal(request, tenant, "principal"),
                **body.model_dump(),
            )
        )

    @router.get("/collections/{collection_id}")
    async def collection_detail(
        request: Request,
        collection_id: ObjectPath,
    ) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.get_collection,
                tenant,
                collection_id,
                principal_ref=_principal(request, tenant, "principal"),
            )
        )

    @router.post("/collections/{collection_id}/access")
    async def grant_collection_access(
        request: Request,
        collection_id: ObjectPath,
        body: CollectionGrantIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.grant_collection_access,
                tenant,
                collection_id,
                actor_ref=_principal(request, tenant, "principal"),
                **body.model_dump(),
            )
        )

    @router.post("/collections/{collection_id}/documents")
    async def add_collection_document(
        request: Request,
        collection_id: ObjectPath,
        body: CollectionDocumentIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.add_collection_document,
                tenant,
                collection_id,
                actor_ref=_principal(request, tenant, "principal"),
                **body.model_dump(),
            )
        )

    @router.post("/collections/{collection_id}/shares/{share_id}")
    async def create_share(
        request: Request,
        collection_id: ObjectPath,
        share_id: ObjectPath,
        body: ShareIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.create_share,
                tenant,
                collection_id,
                share_id=share_id,
                actor_ref=_principal(request, tenant, "principal"),
                **body.model_dump(),
            )
        )

    @router.post("/shares/redeem")
    async def redeem_share(request: Request, body: RedeemShareIn) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        collection = await call(
            ops,
            store.redeem_share,
            body.token,
            scope=body.scope,
        )
        if collection.tenant_id != tenant:
            raise HTTPException(status_code=403, detail="share is not valid for tenant")
        return _jsonable(collection)

    @router.post("/shares/{share_id}/revoke")
    async def revoke_share(request: Request, share_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_share,
                tenant,
                share_id,
                actor_ref=_principal(request, tenant, "principal"),
            )
        )

    @router.put("/subscriptions/{subscription_id}")
    async def save_subscription(
        request: Request,
        subscription_id: ObjectPath,
        body: SubscriptionIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.save_query,
                tenant,
                subscription_id=subscription_id,
                principal_ref=_principal(request, tenant, "principal"),
                **body.model_dump(),
            )
        )

    @router.get("/subscriptions/due")
    async def due_subscriptions(
        request: Request,
        limit: int = Query(default=100, ge=1, le=100),
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        rows = await call(ops, store.due_subscriptions, tenant, limit=limit)
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/subscriptions/{subscription_id}/advance")
    async def advance_subscription(
        request: Request,
        subscription_id: ObjectPath,
        body: RevisionIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.advance_subscription,
                tenant,
                subscription_id,
                actor_ref=_principal(request, tenant, "actor"),
                **body.model_dump(),
            )
        )

    @router.post("/subscriptions/{subscription_id}/revoke")
    async def revoke_subscription(
        request: Request,
        subscription_id: ObjectPath,
        body: RevisionIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_subscription,
                tenant,
                subscription_id,
                actor_ref=_principal(request, tenant, "actor"),
                **body.model_dump(),
            )
        )

    @router.post("/documents/{document_id}/alerts")
    async def generate_alerts(
        request: Request,
        document_id: ObjectPath,
        body: GenerateAlertsIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        rows = await call(
            ops,
            store.generate_alerts,
            tenant,
            document_id,
            body.version,
            actor_ref=_principal(request, tenant, "actor"),
        )
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/deliveries/claim")
    async def claim_deliveries(
        request: Request,
        body: ClaimDeliveriesIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        rows = await call(
            ops,
            store.claim_deliveries,
            tenant,
            worker_id=_principal(request, tenant, "worker"),
            **body.model_dump(),
        )
        return {"items": _jsonable(rows), "count": len(rows)}

    @router.post("/deliveries/run")
    async def run_deliveries(
        request: Request,
        body: RunDeliveriesIn,
    ) -> dict[str, Any]:
        """Run the explicit external email/notification side-effect boundary."""

        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        resolver = getattr(
            request.app.state,
            "privacy_intelligence_destination_resolver",
            None,
        )
        if not callable(resolver):
            raise HTTPException(
                status_code=503,
                detail="privacy-intelligence destination resolver is not configured",
            )
        from maverick import privacy_regulatory_intelligence_delivery as delivery

        transport = getattr(
            request.app.state,
            "privacy_intelligence_delivery_transport",
            None,
        ) or delivery.SmtpPrivacyAlertTransport()
        try:
            result = await run_in_threadpool(
                delivery.deliver_alert_batch,
                store,
                tenant_id=tenant,
                worker_id=_principal(request, tenant, "worker"),
                resolve_destination=resolver,
                transport=transport,
                **body.model_dump(),
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.PrivacyRegulatoryIntelligenceError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-intelligence delivery batch failed",
            ) from exc
        return _jsonable(result)

    @router.post("/deliveries/{delivery_id}/fail")
    async def fail_delivery(
        request: Request,
        delivery_id: ObjectPath,
        body: FailDeliveryIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.fail_delivery,
                tenant,
                delivery_id,
                **body.model_dump(),
            )
        )

    @router.post("/deliveries/{delivery_id}/acknowledge")
    async def acknowledge_delivery(
        request: Request,
        delivery_id: ObjectPath,
        body: AcknowledgeDeliveryIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.acknowledge_delivery,
                tenant,
                delivery_id,
                **body.model_dump(),
            )
        )

    @router.put("/reports/{report_id}")
    async def export_report(
        request: Request,
        report_id: ObjectPath,
        body: ReportIn,
    ) -> dict[str, Any]:
        require_permission(request, "operate")
        ops, tenant, store = authority(request)
        report = await call(
            ops,
            store.export_report,
            tenant,
            report_id=report_id,
            actor_ref=_principal(request, tenant, "actor"),
            **body.model_dump(),
        )
        return report.export()

    @router.get("/reports/{report_id}")
    async def report_detail(request: Request, report_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        report = await call(ops, store.get_report, tenant, report_id)
        return report.export()

    @router.get("/integrity")
    async def verify_integrity(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        ops, tenant, store = authority(request)
        verification = _jsonable(
            await call(ops, store.verify_integrity, tenant)
        )
        verification["valid"] = True
        return verification

    @router.post("/retention/purge")
    async def purge_retention(request: Request) -> dict[str, Any]:
        require_global_permission(request, "admin")
        ops, tenant, store = authority(request)
        return _jsonable(
            await call(
                ops,
                store.purge_expired,
                tenant,
                actor_ref=_principal(request, tenant, "actor"),
            )
        )

    return router


router = create_privacy_intelligence_router()

__all__ = [
    "PrivacyIntelligenceDependencies",
    "create_privacy_intelligence_router",
    "router",
]
