"""Administrative enrollment and revocation for the public consent API."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(prefix="/consent/public-clients", tags=["public-consent-admin"])

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_DIGEST = r"^[0-9a-f]{64}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PublicClientCreateIn(_StrictModel):
    property_id: str = Field(pattern=_ID)
    client_kind: Literal["browser", "service"]
    browser_origin: str | None = Field(default=None, max_length=2048)
    service_client_id: str | None = Field(default=None, pattern=_ID)
    target_origin: str | None = Field(default=None, max_length=2048)
    target_bundle_id: str | None = Field(default=None, min_length=3, max_length=255)
    target_platform: Literal["android", "fireos", "ios", "roku", "tizen", "tvos", "webos"] | None = None
    jurisdiction: str = Field(min_length=1, max_length=64)
    country_code: str = Field(min_length=2, max_length=2)
    region_code: str = Field(default="", max_length=32)
    default_locale: str = Field(min_length=2, max_length=64)
    rule_group_id: str = Field(pattern=_ID)
    rule_group_version: int = Field(ge=1, le=2**31 - 1)
    policy_id: str = Field(pattern=_ID)
    policy_version: int = Field(ge=1, le=2**31 - 1)
    expires_at: float | None = Field(default=None, gt=0)


class ClientRevokeIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)


class ProfileRevokeIn(_StrictModel):
    property_id: str = Field(pattern=_ID)
    evidence_sha256: str = Field(pattern=_DIGEST)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before managing public consent clients",
        )
    return tenant


def _enabled() -> bool:
    from maverick import config

    try:
        if config.config_source_errors():
            return False
        consent = config.load_config().get("consent_preferences", {})
    except Exception:
        return False
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    return all(
        isinstance(consent.get(name), Mapping)
        and consent[name].get("enable") is True
        for name in ("publishing", "public_api")
    )


def _require_enabled() -> None:
    if not _enabled():
        raise HTTPException(
            status_code=403,
            detail="public consent requires consent, publishing, and public_api gates",
        )


def _registry():
    from maverick.paths import data_dir

    from .consent_public_api import PublicConsentCredentialStore

    return PublicConsentCredentialStore(
        data_dir(
            "consent_public_api",
            "public-consent-credentials.sqlite3",
            tenant=None,
        )
    )


def _publishing_store(tenant_id: str):
    from maverick.consent_publishing import ConsentPublishingStore
    from maverick.paths import data_dir

    return ConsentPublishingStore(
        data_dir(
            "consent_preferences",
            "consent-publishing.sqlite3",
            tenant=tenant_id,
        )
    )


def _preference_store(tenant_id: str):
    from maverick.consent_preferences import ConsentPreferenceStore
    from maverick.paths import data_dir

    return ConsentPreferenceStore(
        data_dir(
            "consent_preferences",
            "consent-preferences.sqlite3",
            tenant=tenant_id,
        )
    )


def _actor_sha256(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None) or "local-operator"
    return hashlib.sha256(f"public-consent-admin\0{subject}".encode()).hexdigest()


def _active_policy(
    store,
    tenant: str,
    policy_id: str,
    version: int,
    evaluated_at: float,
) -> dict[str, Any]:
    policy = store.get_active_policy(tenant, policy_id, version=version, at=evaluated_at)
    if not isinstance(policy, dict):
        raise ValueError("the requested policy version is not active")
    return policy


def _derive_binding(tenant: str, body: PublicClientCreateIn) -> dict[str, Any]:
    publishing = _publishing_store(tenant)
    configuration = publishing.resolve_public_configuration(
        tenant,
        body.property_id,
        server_origin=(body.browser_origin if body.client_kind == "browser" else body.target_origin),
        server_bundle_id=body.target_bundle_id,
        server_platform=body.target_platform,
        jurisdiction=body.jurisdiction,
        country_code=body.country_code,
        region_code=body.region_code,
        requested_locale=body.default_locale,
    )
    if configuration.get("allowed") is not True:
        raise ValueError(
            f"published configuration cannot authorize this client: {configuration.get('reason')}"
        )
    preview = publishing.preview(
        tenant,
        body.property_id,
        body.rule_group_id,
        body.rule_group_version,
    )
    publication = configuration.get("publication")
    bundle = preview.get("bundle")
    property_record = bundle.get("property") if isinstance(bundle, dict) else None
    if (
        not isinstance(publication, dict)
        or not isinstance(property_record, dict)
        or preview.get("bundle_sha256") != publication.get("bundle_sha256")
        or property_record.get("revision") != configuration["property"].get("revision")
    ):
        raise ValueError("the requested rule group is not the active publication")
    policy = _active_policy(
        _preference_store(tenant),
        tenant,
        body.policy_id,
        body.policy_version,
        float(configuration["evaluated_at"]),
    )
    content = configuration.get("configuration")
    if not isinstance(content, dict):
        raise ValueError("published configuration is unavailable")
    purposes = content.get("purposes")
    notice = content.get("notice")
    if not isinstance(purposes, list) or not isinstance(notice, dict):
        raise ValueError("published configuration is unavailable")
    published_purposes = {
        str(item.get("id")): str(item.get("lawful_basis"))
        for item in purposes
        if isinstance(item, dict)
    }
    if (
        len(published_purposes) != len(purposes)
        or published_purposes != policy.get("purposes")
        or notice.get("document_sha256") != policy.get("notice_sha256")
    ):
        raise ValueError("published experience and receipt policy do not match")
    return {
        "property_revision": int(property_record["revision"]),
        "property_sha256": str(property_record["record_sha256"]),
        "publication_sha256": str(publication["publication_sha256"]),
        "bundle_sha256": str(publication["bundle_sha256"]),
        "policy_sha256": str(policy["policy_sha256"]),
    }


@router.post("", status_code=201)
async def create_client(request: Request, body: PublicClientCreateIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _require_enabled()
    tenant = _tenant_id()
    try:
        derived = await run_in_threadpool(_derive_binding, tenant, body)
        raw_credential = "lwcp_" + secrets.token_urlsafe(36)
        binding = await run_in_threadpool(
            _registry().enroll_client,
            raw_credential,
            tenant_id=tenant,
            expected_revision=0,
            **body.model_dump(),
            **derived,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        from maverick.consent_publishing import ConsentPublishingError

        from .consent_public_api import PublicConsentError

        if isinstance(exc, (ConsentPublishingError, PublicConsentError)):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise
    safe = dict(binding.__dict__)
    safe.pop("credential_sha256", None)
    return {
        **safe,
        "client_credential": raw_credential,
        "credential_returned_once": True,
    }


@router.get("")
async def list_clients(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    require_global_permission(request, "audit")
    _require_enabled()
    try:
        return await run_in_threadpool(
            _registry().list_clients, _tenant_id(), limit=limit, offset=offset
        )
    except Exception as exc:
        from .consent_public_api import PublicConsentError

        if isinstance(exc, PublicConsentError):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise


@router.get("/profiles")
async def list_profile_bindings(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return only the safe selectors/revisions needed for governed setup."""

    require_global_permission(request, "audit")
    _require_enabled()
    tenant = _tenant_id()
    try:
        result = await run_in_threadpool(
            _registry().list_profile_bindings,
            tenant,
            limit=limit,
        )
        preferences = _preference_store(tenant)
        items: list[dict[str, Any]] = []
        for item in result["items"]:
            authority = await run_in_threadpool(
                preferences.get_profile_authority,
                tenant,
                item["profile_id"],
            )
            items.append(
                {
                    **item,
                    "profile_revision": int(authority["revision"]),
                }
            )
        return {
            "schema": "lightwork.public-consent-profile-bindings.v1",
            "items": items,
            "truncated": result["truncated"],
            "raw_credentials_returned": False,
            "subject_identifiers_returned": False,
        }
    except Exception as exc:
        from maverick.consent_preferences import ConsentPreferencesError

        from .consent_public_api import PublicConsentError

        if isinstance(exc, (ConsentPreferencesError, PublicConsentError)):
            raise HTTPException(
                status_code=503,
                detail="public profile authority is unavailable",
            ) from exc
        raise


@router.post("/{credential_id}/revoke")
async def revoke_client(
    request: Request,
    credential_id: str,
    body: ClientRevokeIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _require_enabled()
    try:
        return await run_in_threadpool(
            _registry().revoke_client_id,
            _tenant_id(),
            credential_id,
            expected_revision=body.expected_revision,
        )
    except Exception as exc:
        from .consent_public_api import (
            PublicConsentConflict,
            PublicConsentCredentialError,
            PublicConsentError,
        )

        if isinstance(exc, PublicConsentCredentialError):
            raise HTTPException(status_code=404, detail="public client not found") from exc
        if isinstance(exc, PublicConsentConflict):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if isinstance(exc, PublicConsentError):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise


@router.post("/profiles/{profile_id}/revoke")
async def revoke_profile(
    request: Request,
    profile_id: str,
    body: ProfileRevokeIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _require_enabled()
    try:
        return await run_in_threadpool(
            _registry().revoke_profile,
            _tenant_id(),
            body.property_id,
            profile_id,
            actor_sha256=_actor_sha256(request),
            evidence_sha256=body.evidence_sha256,
        )
    except Exception as exc:
        from .consent_public_api import PublicConsentCredentialError, PublicConsentError

        if isinstance(exc, PublicConsentCredentialError):
            raise HTTPException(status_code=404, detail="public profile not found") from exc
        if isinstance(exc, PublicConsentError):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise


__all__ = ["router"]
