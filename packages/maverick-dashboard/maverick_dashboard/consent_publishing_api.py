"""Administrative REST surface for immutable consent experience publishing."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/consent/publishing", tags=["consent-publishing"])

_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST = r"^[0-9a-f]{64}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _VersionMutation(_StrictModel):
    version: int = Field(..., ge=1, le=2**31 - 1)
    expected_current_version: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class PropertyIn(_StrictModel):
    kind: Literal["web", "mobile"]
    consent_group_id: str = Field(..., pattern=_ID)
    expected_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)
    web_domains: list[str] = Field(default_factory=list, max_length=64)
    origin_allowlist: list[str] = Field(default_factory=list, max_length=64)
    mobile_bundle_ids: list[str] = Field(default_factory=list, max_length=64)
    platform: Literal["android", "fireos", "ios", "roku", "tizen", "tvos", "webos"] | None = None


class PurposeIn(_VersionMutation):
    title_key: str = Field(..., pattern=_ID)
    description_key: str = Field(..., pattern=_ID)
    lawful_basis: Literal[
        "consent",
        "contract",
        "legal_obligation",
        "legitimate_interests",
        "public_task",
        "vital_interests",
    ]
    required: bool
    default_choice: Literal["denied", "granted", "unset"]


class TopicIn(_VersionMutation):
    purpose_id: str = Field(..., pattern=_ID)
    purpose_version: int = Field(..., ge=1, le=2**31 - 1)
    title_key: str = Field(..., pattern=_ID)
    description_key: str = Field(..., pattern=_ID)
    default_choice: Literal["denied", "granted", "unset"]


class CustomPreferenceIn(_VersionMutation):
    title_key: str = Field(..., pattern=_ID)
    description_key: str = Field(..., pattern=_ID)
    value_type: Literal["boolean", "multi_select", "single_select"]
    option_ids: list[str] = Field(default_factory=list, max_length=64)
    required: bool


class NoticeIn(_VersionMutation):
    title_key: str = Field(..., pattern=_ID)
    body_key: str = Field(..., pattern=_ID)
    document_sha256: str = Field(..., pattern=_DIGEST)


class TranslationIn(_VersionMutation):
    messages: dict[str, str] = Field(..., min_length=1, max_length=256)


class TemplateIn(_VersionMutation):
    surface: Literal["banner", "mobile_sheet", "modal", "preferences_center"]
    title_key: str = Field(..., pattern=_ID)
    body_key: str = Field(..., pattern=_ID)
    actions: dict[
        Literal[
            "accept_all",
            "close",
            "manage_preferences",
            "reject_all",
            "save_preferences",
        ],
        str,
    ] = Field(..., min_length=1, max_length=5)
    theme_token_id: str = Field(..., pattern=_ID)
    theme_token_version: int | None = Field(default=None, ge=1, le=2**31 - 1)


class ThemeTokenIn(_VersionMutation):
    display_name_key: str = Field(..., pattern=_ID)
    heading_key: str = Field(..., pattern=_ID)
    description_key: str = Field(..., pattern=_ID)
    primary_color: str = Field(..., pattern=r"^[0-9a-fA-F]{6}$")
    primary_text_color: str = Field(..., pattern=r"^[0-9a-fA-F]{6}$")
    surface_color: str = Field(..., pattern=r"^[0-9a-fA-F]{6}$")
    text_color: str = Field(..., pattern=r"^[0-9a-fA-F]{6}$")


class VersionRefIn(_StrictModel):
    id: str = Field(..., pattern=_ID)
    version: int = Field(..., ge=1, le=2**31 - 1)


class RuleIn(_StrictModel):
    rule_id: str = Field(..., pattern=_ID)
    priority: int = Field(..., ge=0, le=1_000_000)
    jurisdictions: list[str] = Field(default_factory=list, max_length=64)
    country_codes: list[str] = Field(default_factory=list, max_length=64)
    region_codes: list[str] = Field(default_factory=list, max_length=64)
    locales: list[str] = Field(..., min_length=1, max_length=32)
    default_locale: str = Field(..., min_length=2, max_length=64)
    consent_mode: Literal["notice_only", "opt_in", "opt_out"] = "opt_in"
    purposes: list[VersionRefIn] = Field(default_factory=list, max_length=128)
    topics: list[VersionRefIn] = Field(default_factory=list, max_length=128)
    custom_preferences: list[VersionRefIn] = Field(default_factory=list, max_length=128)
    notice: VersionRefIn
    template: VersionRefIn
    translation_catalog_id: str = Field(..., pattern=_ID)
    translation_versions: dict[str, int] = Field(..., min_length=1, max_length=32)


class RuleGroupIn(_VersionMutation):
    rules: list[RuleIn] = Field(..., min_length=1, max_length=128)


class PreviewIn(_StrictModel):
    rule_group_id: str = Field(..., pattern=_ID)
    rule_group_version: int = Field(..., ge=1, le=2**31 - 1)


class PublishIn(PreviewIn):
    expected_property_revision: int = Field(..., ge=0, le=2**31 - 1)
    expected_publication_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class RollbackIn(_StrictModel):
    target_publication_id: str = Field(..., pattern=_ID)
    expected_property_revision: int = Field(..., ge=0, le=2**31 - 1)
    expected_publication_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


class WithdrawIn(_StrictModel):
    expected_property_revision: int = Field(..., ge=0, le=2**31 - 1)
    expected_publication_revision: int = Field(..., ge=0, le=2**31 - 1)
    idempotency_key: str = Field(..., pattern=_IDEMPOTENCY)


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent publishing",
        )
    return tenant


def _ops():
    from maverick import config, consent_publishing

    try:
        if config.config_source_errors():
            raise ValueError("configuration is invalid")
        product = config.load_config().get("consent_preferences", {})
    except Exception:
        product = {}
    publishing = product.get("publishing") if isinstance(product, Mapping) else None
    if not (
        isinstance(product, Mapping)
        and product.get("enable") is True
        and isinstance(publishing, Mapping)
        and publishing.get("enable") is True
    ):
        raise HTTPException(
            status_code=403,
            detail=("consent publishing is disabled ([consent_preferences.publishing] enable)"),
        )
    return consent_publishing


def _store(ops, tenant_id: str):
    from maverick.paths import data_dir

    return ops.ConsentPublishingStore(
        data_dir(
            "consent_preferences",
            "consent-publishing.sqlite3",
            tenant=tenant_id,
        )
    )


async def _call(ops, function, *args, **kwargs) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except (ops.PublishingConflict, ops.PublishingIdempotencyConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.PublishingNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.PublishingValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ConsentPublishingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _authority():
    ops = _ops()
    tenant = _tenant_id()
    return ops, tenant, _store(ops, tenant)


_CATALOG_KINDS = {"properties":"property", "purposes":"purpose", "topics":"topic",
                  "custom-preferences":"custom_preference", "notices":"notice", "translations":"translation",
                  "templates":"template", "themes":"theme", "rule-groups":"rule_group"}


def _catalog_authority(request: Request):
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    expected = request.headers.get("X-Lightwork-Expected-Tenant")
    if expected is not None and expected != tenant:
        raise HTTPException(status_code=409, detail="The active workspace changed. Reload before choosing saved consent records.")
    return ops, tenant, store


@router.get("/catalog/{kind}")
async def catalog(request: Request, kind: str, q: str = Query("", max_length=200),
                  resource_id: str = Query("", max_length=128), offset: int = Query(0, ge=0, le=1_000_000),
                  limit: int = Query(25, ge=1, le=50)) -> dict:
    if kind not in _CATALOG_KINDS:
        raise HTTPException(status_code=422, detail="unknown consent resource kind")
    ops, tenant, store = _catalog_authority(request)
    return await _call(ops, store.catalog, tenant, kind=_CATALOG_KINDS[kind], query=q,
                       resource_id=resource_id, offset=offset, limit=limit)


@router.get("/catalog/{kind}/{resource_id}/versions/{version}")
async def catalog_version(request: Request, kind: str, resource_id: str, version: int,
                          locale: str = Query("", max_length=64)) -> dict:
    if kind not in _CATALOG_KINDS or kind == "properties":
        raise HTTPException(status_code=422, detail="unknown consent resource kind")
    ops, tenant, store = _catalog_authority(request)
    return await _call(ops, store.resource_version, tenant, _CATALOG_KINDS[kind], resource_id, version, locale=locale)


@router.put("/properties/{property_id}")
async def upsert_property(request: Request, property_id: str, body: PropertyIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    return await _call(ops, store.upsert_property, tenant, property_id, **body.model_dump())


@router.post("/purposes/{purpose_id}/versions", status_code=201)
async def put_purpose(request: Request, purpose_id: str, body: PurposeIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(ops, store.put_purpose_version, tenant, purpose_id, version, **payload)


@router.post("/topics/{topic_id}/versions", status_code=201)
async def put_topic(request: Request, topic_id: str, body: TopicIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(ops, store.put_topic_version, tenant, topic_id, version, **payload)


@router.post("/custom-preferences/{preference_id}/versions", status_code=201)
async def put_custom_preference(
    request: Request,
    preference_id: str,
    body: CustomPreferenceIn,
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(
        ops,
        store.put_custom_preference_version,
        tenant,
        preference_id,
        version,
        **payload,
    )


@router.post("/notices/{notice_id}/versions", status_code=201)
async def put_notice(request: Request, notice_id: str, body: NoticeIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(ops, store.put_notice_version, tenant, notice_id, version, **payload)


@router.post("/translations/{catalog_id}/{locale}/versions", status_code=201)
async def put_translation(
    request: Request,
    catalog_id: str,
    locale: str,
    body: TranslationIn,
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(
        ops,
        store.put_translation_version,
        tenant,
        catalog_id,
        locale,
        version,
        **payload,
    )


@router.post("/templates/{template_id}/versions", status_code=201)
async def put_template(request: Request, template_id: str, body: TemplateIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(ops, store.put_template_version, tenant, template_id, version, **payload)


@router.post("/themes/{theme_token_id}/versions", status_code=201)
async def put_theme_token(
    request: Request,
    theme_token_id: str,
    body: ThemeTokenIn,
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(
        ops,
        store.put_theme_token_version,
        tenant,
        theme_token_id,
        version,
        **payload,
    )


@router.post("/rule-groups/{rule_group_id}/versions", status_code=201)
async def put_rule_group(
    request: Request,
    rule_group_id: str,
    body: RuleGroupIn,
) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    version = payload.pop("version")
    return await _call(
        ops,
        store.put_rule_group_version,
        tenant,
        rule_group_id,
        version,
        **payload,
    )


@router.post("/properties/{property_id}/preview")
async def preview(request: Request, property_id: str, body: PreviewIn) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.preview,
        tenant,
        property_id,
        body.rule_group_id,
        body.rule_group_version,
    )


@router.post("/properties/{property_id}/publish", status_code=201)
async def publish(request: Request, property_id: str, body: PublishIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    rule_group_id = payload.pop("rule_group_id")
    rule_group_version = payload.pop("rule_group_version")
    return await _call(
        ops,
        store.publish,
        tenant,
        property_id,
        rule_group_id,
        rule_group_version,
        **payload,
    )


@router.post("/properties/{property_id}/rollback", status_code=201)
async def rollback(request: Request, property_id: str, body: RollbackIn) -> dict:
    require_global_permission(request, "admin")
    ops, tenant, store = _authority()
    payload = body.model_dump()
    target = payload.pop("target_publication_id")
    return await _call(ops, store.rollback, tenant, property_id, target, **payload)


@router.post("/properties/{property_id}/withdraw", status_code=201)
async def withdraw(request: Request, property_id: str, body: WithdrawIn) -> dict:
    """Replace the exact active head with a locally constructed tombstone."""

    from . import consent_publication_withdrawal

    require_global_permission(request, "admin")
    return await run_in_threadpool(consent_publication_withdrawal.legacy, request, property_id, body.model_dump())


@router.get("/properties/{property_id}/history")
async def history(
    request: Request,
    property_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    require_permission(request, "operate")
    ops, tenant, store = _authority()
    return await _call(
        ops,
        store.publication_history,
        tenant,
        property_id,
        limit=limit,
    )


__all__ = ["router"]
