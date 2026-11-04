"""Strict authenticated operator API for Trust Center branding authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission
from .trust_center_branding_composition import trust_center_branding_enabled

IdValue = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    ),
]
IdPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AssetProposalIn(_Strict):
    expected_version: int = Field(ge=0, le=2_147_483_646)
    asset_kind: str = Field(pattern=r"^(?:logo|icon)$")
    media_type: str = Field(pattern=r"^image/(?:png|jpeg)$")
    content_base64: str = Field(min_length=4, max_length=14_000_000)


class AuthorityRevisionIn(_Strict):
    expected_authority_revision: int = Field(ge=1, le=2_147_483_647)


class AssetReviewIn(AuthorityRevisionIn):
    approve: bool


class CustodyRotationIn(_Strict):
    expected_custody_revision: int = Field(ge=1, le=2_147_483_647)


class PurgeIn(_Strict):
    before: float = Field(gt=0, lt=100_000_000_000.0)
    limit: int = Field(default=100, ge=1, le=500)


class DomainChallengeIn(_Strict):
    host: str = Field(min_length=3, max_length=253)
    expected_claim_version: int = Field(ge=0, le=2_147_483_646)


class ProjectionBindIn(_Strict):
    client_credential_id: IdValue
    asset_id: IdValue
    asset_version: int = Field(ge=1, le=2_147_483_647)
    domain_claim_id: IdValue | None = None
    domain_claim_version: int | None = Field(default=None, ge=1, le=2_147_483_647)
    expected_projection_revision: int = Field(ge=0, le=2_147_483_646)


class ProjectionRevokeIn(_Strict):
    expected_projection_revision: int = Field(ge=1, le=2_147_483_647)


router = APIRouter(
    prefix="/consent/trust-center-branding",
    tags=["consent-trust-center-branding"],
)

_PRIVATE = {
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


def _private(response: Response) -> None:
    for key, value in _PRIVATE.items():
        response.headers[key] = value


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    value = current_tenant_id_strict()
    if value is None:
        raise HTTPException(status_code=409, detail="select an active tenant")
    return value


def _actor(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(request, error_detail="authenticated principal required")
    return "brand-actor-" + hashlib.sha256(
        f"lightwork.trust-center-brand.api.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()[:32]


def _store(request: Request):
    if not trust_center_branding_enabled():
        raise HTTPException(status_code=403, detail="Trust Center branding is disabled")
    tenant = _tenant_id()
    factory = getattr(request.app.state, "trust_center_branding_store_factory", None)
    if not callable(factory):
        raise HTTPException(status_code=503, detail="Trust Center branding unavailable")
    try:
        return tenant, _actor(request, tenant), factory(tenant_id=tenant, request=request)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Trust Center branding unavailable") from exc


async def _call(function, *args, **kwargs):
    from maverick import trust_center_branding as ops

    try:
        value = await run_in_threadpool(function, *args, **kwargs)
    except ops.BrandingNotFound as exc:
        raise HTTPException(status_code=404, detail="Trust Center brand record not found") from exc
    except ops.BrandingConflict as exc:
        raise HTTPException(status_code=409, detail="Trust Center brand state changed") from exc
    except ops.BrandingValidationError as exc:
        raise HTTPException(status_code=422, detail="Trust Center brand request invalid") from exc
    except (
        ops.BrandingConfigError,
        ops.BrandingExternalAuthorityError,
        ops.BrandingIntegrityError,
    ) as exc:
        raise HTTPException(status_code=503, detail="Trust Center branding unavailable") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Trust Center branding operation failed") from exc
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    return value


@router.get("/status")
async def status(request: Request, response: Response) -> dict[str, Any]:
    require_permission(request, "view")
    _private(response)
    enabled = trust_center_branding_enabled()
    result: dict[str, Any] = {
        "schema": "lightwork.trust-center-branding-runtime-status.v1",
        "enabled": enabled,
        "store_factory_configured": callable(
            getattr(request.app.state, "trust_center_branding_store_factory", None)
        ),
        "key_resolver_configured": callable(
            getattr(request.app.state, "trust_center_branding_key_resolver", None)
        ),
        "domain_deployment_authority_configured": all(
            callable(getattr(
                getattr(request.app.state, "trust_center_domain_deployment_authority", None),
                name,
                None,
            ))
            for name in ("verify", "activate", "reverify", "revoke")
        ),
        "live_dns_tls_cdn_acceptance_proven": False,
        "accessibility_brand_customer_acceptance_proven": False,
    }
    if enabled:
        _tenant, _principal, store = _store(request)
        result["authority"] = await _call(store.status)
    return result


@router.get("/assets")
async def list_assets(request: Request, response: Response) -> dict[str, Any]:
    """Every logo and icon version with its review state, newest first."""

    require_permission(request, "view")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    items = await _call(store.list_assets, limit=200)
    return {"items": [asdict(item) for item in items]}


@router.get("/domains")
async def list_domains(request: Request, response: Response) -> dict[str, Any]:
    """Every custom web address claim with its state, newest first."""

    require_permission(request, "view")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    items = await _call(store.list_domains, limit=200)
    return {"items": [asdict(item) for item in items]}


@router.get("/projections")
async def list_projections(request: Request, response: Response) -> dict[str, Any]:
    """The brand shown on each website, with its revision."""

    require_permission(request, "view")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    items = await _call(store.list_projections, limit=200)
    return {"items": [asdict(item) for item in items]}


@router.post("/assets/{asset_id}/versions", status_code=201)
async def propose_asset(
    asset_id: IdPath, body: AssetProposalIn, request: Request, response: Response
) -> dict[str, Any]:
    require_permission(request, "operate")
    _private(response)
    try:
        content = base64.b64decode(body.content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="Trust Center brand request invalid") from exc
    _tenant, actor, store = _store(request)
    return await _call(
        store.propose_asset,
        asset_id,
        expected_version=body.expected_version,
        asset_kind=body.asset_kind,
        media_type=body.media_type,
        content=content,
        actor_ref=actor,
    )


@router.get("/assets/{asset_id}/versions/{asset_version}")
async def get_asset(
    asset_id: IdPath,
    asset_version: int,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_permission(request, "view")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    return await _call(store.get_asset, asset_id, asset_version)


@router.post("/assets/{asset_id}/versions/{asset_version}/review")
async def review_asset(
    asset_id: IdPath,
    asset_version: int,
    body: AssetReviewIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    return await _call(
        store.review_asset,
        asset_id,
        asset_version,
        expected_authority_revision=body.expected_authority_revision,
        actor_ref=actor,
        approve=body.approve,
    )


async def _asset_authority_action(
    action: str,
    asset_id: str,
    asset_version: int,
    body: AuthorityRevisionIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    return await _call(
        getattr(store, action),
        asset_id,
        asset_version,
        expected_authority_revision=body.expected_authority_revision,
        actor_ref=actor,
    )


@router.post("/assets/{asset_id}/versions/{asset_version}/activate")
async def activate_asset(asset_id: IdPath, asset_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _asset_authority_action("activate_asset", asset_id, asset_version, body, request, response)


@router.post("/assets/{asset_id}/versions/{asset_version}/revoke")
async def revoke_asset(asset_id: IdPath, asset_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _asset_authority_action("revoke_asset", asset_id, asset_version, body, request, response)


@router.post("/assets/{asset_id}/versions/{asset_version}/rotate-custody")
async def rotate_custody(asset_id: IdPath, asset_version: int, body: CustodyRotationIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    return await _call(store.rotate_asset_custody, asset_id, asset_version, expected_custody_revision=body.expected_custody_revision, actor_ref=actor)


@router.post("/retention/purge")
async def purge(body: PurgeIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    return await _call(store.purge_assets, before=body.before, limit=body.limit)


@router.post("/domains/{claim_id}/challenges", status_code=201)
async def challenge_domain(claim_id: IdPath, body: DomainChallengeIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    value = await _call(store.challenge_domain, claim_id, body.host, expected_claim_version=body.expected_claim_version, actor_ref=actor)
    if not isinstance(value, tuple) or len(value) != 2:
        raise HTTPException(status_code=503, detail="Trust Center branding unavailable")
    authority, token = value
    return {"authority": asdict(authority), "dns_challenge_token": token}


async def _domain_action(action: str, claim_id: str, claim_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    value = await _call(getattr(store, action), claim_id, claim_version, expected_authority_revision=body.expected_authority_revision, actor_ref=actor)
    if isinstance(value, tuple):
        authority, confirmed = value
        return {"authority": asdict(authority), "deployment_revocation_confirmed": confirmed}
    return value


@router.post("/domains/{claim_id}/versions/{claim_version}/verify")
async def verify_domain(claim_id: IdPath, claim_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _domain_action("verify_domain", claim_id, claim_version, body, request, response)


@router.post("/domains/{claim_id}/versions/{claim_version}/activate")
async def activate_domain(claim_id: IdPath, claim_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _domain_action("activate_domain", claim_id, claim_version, body, request, response)


@router.post("/domains/{claim_id}/versions/{claim_version}/reverify")
async def reverify_domain(claim_id: IdPath, claim_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _domain_action("reverify_domain", claim_id, claim_version, body, request, response)


@router.post("/domains/{claim_id}/versions/{claim_version}/revoke")
async def revoke_domain(claim_id: IdPath, claim_version: int, body: AuthorityRevisionIn, request: Request, response: Response):
    return await _domain_action("revoke_domain", claim_id, claim_version, body, request, response)


@router.post("/domains/maintenance/expire")
async def expire_domains(request: Request, response: Response, limit: int = 100):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, _actor_ref, store = _store(request)
    return await _call(store.expire_domains, limit=limit)


@router.put("/projections/{property_id}", status_code=201)
async def bind_projection(property_id: IdPath, body: ProjectionBindIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    return await _call(
        store.bind_projection,
        property_id,
        body.client_credential_id,
        asset_id=body.asset_id,
        asset_version=body.asset_version,
        domain_claim_id=body.domain_claim_id,
        domain_claim_version=body.domain_claim_version,
        expected_projection_revision=body.expected_projection_revision,
        actor_ref=actor,
    )


@router.post("/projections/{property_id}/revoke")
async def revoke_projection(property_id: IdPath, body: ProjectionRevokeIn, request: Request, response: Response):
    require_global_permission(request, "admin")
    _private(response)
    _tenant, actor, store = _store(request)
    return await _call(store.revoke_projection, property_id, expected_projection_revision=body.expected_projection_revision, actor_ref=actor)


__all__ = ["router"]
