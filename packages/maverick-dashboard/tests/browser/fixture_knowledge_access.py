"""Local synthetic APP10 service for browser-to-real-API acceptance."""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict

from fastapi import HTTPException, Request
from maverick.knowledge_access import (
    KnowledgeAccessService,
    KnowledgeActorAuthority,
    KnowledgeDocument,
)
from maverick.paths import tenant_scope
from maverick.research_registry import (
    DataUseAuthority,
    RegistryReviewAuthority,
    ResearchRegistry,
    ResearchRegistryDenied,
)
from maverick_dashboard.auth import caller_principal
from maverick_dashboard.draft_api import context_for


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def install(app, tenant: str, principal: str) -> None:
    rights = {"allowed": True}
    decision_assets = {"decision-browser-knowledge-source": "browser-knowledge-source"}

    def data_use(current_tenant, decision_id, decision_sha256):
        if (
            current_tenant != tenant
            or decision_id not in decision_assets
            or decision_sha256 != _sha("browser data-use decision")
            or not rights["allowed"]
        ):
            raise ResearchRegistryDenied("synthetic source authority is unavailable")
        return DataUseAuthority(
            tenant=tenant,
            decision_id=decision_id,
            decision_sha256=decision_sha256,
            asset_id=decision_assets[decision_id],
            action="export",
            purpose_codes=("product_research",),
            expires_at=4_102_444_800.0,
            authority_sha256=_sha("browser current data-use authority"),
        )

    registry = ResearchRegistry(
        data_use_resolver=data_use,
        review_authority_resolver=lambda current_tenant, actor: (
            RegistryReviewAuthority(
                current_tenant,
                actor,
                _sha(f"browser registry review:{current_tenant}:{actor}"),
            )
        ),
    )

    def content(current_tenant, reference, admission):
        if current_tenant != tenant or reference.asset_id != "browser-knowledge-source":
            return None
        return KnowledgeDocument(
            tenant=current_tenant,
            reference=reference,
            content_sha256=admission.content_sha256,
            title="Synthetic governed browser policy",
            summary=(
                "This local synthetic policy passed the real APP10 registry, "
                "actor, purpose, source, cache, and API boundaries."
            ),
            claim_state="verified",
            observed_at=1_700_000_000.0,
            verified_at=1_700_000_100.0,
        )

    def actor_authority(current_tenant, actor, action, purpose):
        if current_tenant != tenant or actor != principal:
            raise PermissionError("synthetic actor authority is unavailable")
        return KnowledgeActorAuthority(
            tenant=current_tenant,
            principal=actor,
            action=action,
            purpose=purpose,
            authorization_sha256=_sha(
                f"browser actor:{current_tenant}:{actor}:{action}:{purpose}"
            ),
        )

    service = KnowledgeAccessService(
        registry=registry,
        content_resolver=content,
        actor_authority_resolver=actor_authority,
    )
    with tenant_scope(tenant=tenant):
        reference = registry.register_dataset(
            tenant,
            "user:browser-source-owner",
            dataset_id="browser-knowledge-source",
            version="v1",
            source_ref="catalog:browser-workspace/browser-knowledge-source/v1",
            content_sha256=_sha("browser synthetic knowledge content"),
            license_id="synthetic-fixture-only",
            license_evidence_sha256=_sha("browser synthetic license"),
            allowed_purposes=("product_research",),
            usage_constraints=("tenant_only", "separate_training_permission_required"),
            data_use_action="export",
            data_use_decision_id="decision-browser-knowledge-source",
            data_use_decision_sha256=_sha("browser data-use decision"),
        )
        reference = registry.approve(
            tenant,
            principal,
            reference,
            expected_revision=1,
        )
    app.state.knowledge_access_service = service

    @app.post("/__browser_fixture/knowledge-access/setup", include_in_schema=False)
    async def setup(request: Request):
        if caller_principal(request) != principal:
            raise HTTPException(403, "Only the synthetic fixture owner can use APP10 setup.")
        with tenant_scope(tenant=tenant):
            context = context_for(request)
        return {
            "synthetic": True,
            "provider_calls": 0,
            "outbound_calls": "blocked",
            "context": context,
            "reference": asdict(reference),
        }

    @app.post("/__browser_fixture/knowledge-access/archived-owner", include_in_schema=False)
    async def archived_owner(request: Request):
        if caller_principal(request) != principal:
            raise HTTPException(403, "Only the synthetic fixture owner can prepare this case.")
        with tenant_scope(tenant=tenant):
            asset_id = "browser-knowledge-archive-" + secrets.token_hex(8)
            decision_id = "decision-" + asset_id
            decision_assets[decision_id] = asset_id
            archive_reference = registry.register_dataset(
                tenant,
                "user:browser-source-owner",
                dataset_id=asset_id,
                version="v1",
                source_ref=f"catalog:browser-workspace/{asset_id}/v1",
                content_sha256=_sha("browser synthetic knowledge content"),
                license_id="synthetic-fixture-only",
                license_evidence_sha256=_sha("browser synthetic license"),
                allowed_purposes=("product_research",),
                usage_constraints=("tenant_only", "separate_training_permission_required"),
                data_use_action="export",
                data_use_decision_id=decision_id,
                data_use_decision_sha256=_sha("browser data-use decision"),
            )
            archive_reference = registry.approve(
                tenant, principal, archive_reference, expected_revision=1,
            )
            submitted = service.submit_request(
                tenant, "user:browser-colleague", archive_reference,
                request_type="exclusion", reason="Synthetic colleague archive receipt.",
                request_key="browser-colleague-" + secrets.token_hex(8),
            )
            denied = service.decide_request(
                tenant, principal, submitted["id"],
                expected_revision=submitted["revision"], decision="deny",
                evidence_sha256=_sha("synthetic colleague archive denial"),
            )
            archived = service.archive_request(
                tenant, principal, submitted["id"],
                expected_revision=denied["revision"],
            )
        return {"id": archived["id"], "archived_at": archived["archived_at"]}
