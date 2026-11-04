"""Authenticated operator API for one-time privacy-rights package delivery.

The tenant and acting principal are derived from authenticated server context.
Consumer binding and package authority are constructor-bound trusted resolvers;
neither is accepted from an operator request.  A raw consumer capability may
appear only in the first successful mint response.  There is deliberately no
list, capability-read, redeem, grant-claim, object-byte, or credential route.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_REASON_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"

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
CredentialRef = Annotated[
    str,
    StringConstraints(strict=True, min_length=5, max_length=128, pattern=_KEY_REF_PATTERN),
]
ReasonCode = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_REASON_PATTERN),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MintDeliveryIn(_StrictModel):
    case_id: OpaqueId
    package_id: OpaqueId
    reauthentication_receipt_sha256: Digest
    ttl_seconds: int = Field(ge=30, le=15 * 60)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    max_attempts: int = Field(default=3, ge=1, le=5)
    min_attempt_interval_seconds: int = Field(default=1, ge=0, le=60)
    idempotency_key: IdempotencyKey


class RevokeDeliveryIn(_StrictModel):
    reason_code: ReasonCode
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ExportDeliveryIn(_StrictModel):
    expected_delivery_revision: int = Field(ge=1, le=1_000_000)
    signing_key_ref: CredentialRef
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class EvidenceRecordIn(_StrictModel):
    idempotency_key: IdempotencyKey


#: Signing key the page's "Download evidence record" button uses, so nobody is
#: asked for a key reference. The key itself stays in the environment.
DEFAULT_EVIDENCE_SIGNING_KEY_REF = "env:MAVERICK_PRIVACY_DELIVERY_SIGNING_KEY"


class PurgeDeliveryIn(_StrictModel):
    cutoff: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


def _enabled() -> bool:
    from maverick import privacy_rights_consumer_delivery as delivery

    return delivery.enabled()


def privacy_rights_consumer_delivery_enabled_for_page() -> bool:
    """Read the exact nested feature gate without opening tenant storage."""

    return _enabled()


def _ops():
    from maverick import privacy_rights_consumer_delivery as delivery

    try:
        delivery.require_enabled()
    except delivery.RightsConsumerDeliveryConfigError as exc:
        raise HTTPException(
            status_code=403,
            detail="privacy-rights consumer delivery is disabled",
        ) from exc
    return delivery


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using rights delivery",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for rights delivery",
    )
    digest = hashlib.sha256(
        (f"lightwork.privacy-rights-consumer-delivery.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"prcd-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _expect(value: Any, expected: type | tuple[type, ...]) -> Any:
    if not isinstance(value, expected):
        raise HTTPException(
            status_code=503,
            detail="privacy-rights delivery authority returned an invalid contract",
        )
    return value


def _purge_result(value: Any) -> dict[str, int]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"deliveries", "history", "exports"}
        or any(type(value[key]) is not int or value[key] < 0 for key in value)
    ):
        raise HTTPException(
            status_code=503,
            detail="privacy-rights delivery authority returned an invalid contract",
        )
    return {key: value[key] for key in ("deliveries", "history", "exports")}


async def _body(request: Request, model: type[_StrictModel]) -> _StrictModel:
    """Parse a closed body without reflecting rejected raw fields."""

    try:
        return model.model_validate(await request.json())
    except (ValidationError, ValueError, UnicodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail="privacy-rights delivery request body is invalid",
        ) from exc


def _default_store_for(
    request: Request,
    tenant_id: str,
    principal_ref: str,
):
    """Open tenant-local state only with every trusted resolver injected."""

    from maverick.paths import data_dir
    from maverick.privacy_rights_consumer_delivery import (
        RightsConsumerDeliveryConfigError,
        RightsConsumerDeliveryStore,
    )

    state = request.app.state
    authority_factory = getattr(
        state,
        "privacy_rights_consumer_delivery_authorization_resolver_factory",
        None,
    )
    binding_factory = getattr(
        state,
        "privacy_rights_consumer_delivery_binding_resolver_factory",
        None,
    )
    digest_key_resolver = getattr(
        state,
        "privacy_rights_consumer_delivery_digest_key_resolver",
        None,
    )
    signing_key_resolver = getattr(
        state,
        "privacy_rights_consumer_delivery_signing_key_resolver",
        None,
    )
    if not all(
        callable(value)
        for value in (
            authority_factory,
            binding_factory,
            digest_key_resolver,
            signing_key_resolver,
        )
    ):
        raise RightsConsumerDeliveryConfigError(
            "trusted delivery authority, binding, digest-key, and signing-key resolvers are required"
        )
    context = {
        "tenant_id": tenant_id,
        "principal_ref": principal_ref,
        "request": request,
    }
    authorization_resolver = authority_factory(**context)
    binding_resolver = binding_factory(**context)
    if not callable(authorization_resolver) or not callable(binding_resolver):
        raise RightsConsumerDeliveryConfigError(
            "trusted delivery resolver factories returned an invalid boundary"
        )
    return RightsConsumerDeliveryStore(
        data_dir(
            "privacy_automation",
            "privacy-rights-consumer-delivery.sqlite3",
            tenant=tenant_id,
        ),
        authorization_resolver=authorization_resolver,
        current_consumer_binding_resolver=binding_resolver,
        principal_resolver=lambda: principal_ref,
        digest_key_resolver=digest_key_resolver,
        signing_key_resolver=signing_key_resolver,
    )


class PrivacyRightsConsumerDeliveryDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[Request, str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def create_privacy_rights_consumer_delivery_router(  # noqa: C901
    dependencies: PrivacyRightsConsumerDeliveryDependencies | None = None,
) -> APIRouter:
    deps = dependencies or PrivacyRightsConsumerDeliveryDependencies()
    router = APIRouter(
        prefix="/privacy/rights-consumer-delivery",
        tags=["privacy-rights-consumer-delivery"],
    )

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(
            request.app.state,
            "privacy_rights_consumer_delivery_store_factory",
            None,
        )

        def principal_resolver() -> str:
            return principal

        try:
            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=principal_resolver,
                    request=request,
                )
                if callable(factory)
                else deps.store_for(request, tenant, principal)
            )
        except (ops.RightsConsumerDeliveryError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery authority is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery authority is unavailable",
            )
        required_methods = (
            "mint_delivery",
            "get_delivery",
            "revoke_delivery",
            "export_signed_metadata",
            "get_export",
            "purge_expired",
            "verify_integrity",
        )
        if any(not callable(getattr(store, name, None)) for name in required_methods):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery authority returned an invalid contract",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.RightsConsumerDeliveryNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="privacy-rights delivery record was not found",
            ) from exc
        except (
            ops.RightsConsumerDeliveryPermissionDenied,
            ops.RightsConsumerDeliveryDenied,
        ) as exc:
            raise HTTPException(
                status_code=403,
                detail="privacy-rights delivery operation is not authorized",
            ) from exc
        except ops.RightsConsumerDeliveryConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="privacy-rights delivery state conflict",
            ) from exc
        except ops.RightsConsumerDeliveryValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="privacy-rights delivery request is invalid",
            ) from exc
        except ops.RightsConsumerDeliveryConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery authority is unavailable",
            ) from exc
        except ops.RightsConsumerDeliveryIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery integrity verification failed",
            ) from exc
        except ops.RightsConsumerDeliveryError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-rights delivery operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, Any]:
        require_permission(request, "view")
        _private(response)
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick.privacy_rights_consumer_delivery import (
            RightsConsumerDeliveryStore,
        )

        composition: Mapping[str, object] = {
            "schema": "lightwork.privacy-rights-consumer-delivery-composition-status.v1",
            "enabled": False,
            "ready": False,
            "operator_mint_ready": False,
            "public_delivery_ready": False,
            "identity_inferred_from_package": False,
            "status_probe_opened_tenant_storage": False,
            "status_probe_resolved_secret_value": False,
        }
        readiness_probe = getattr(
            request.app.state,
            "privacy_rights_consumer_delivery_readiness_probe",
            None,
        )
        if callable(readiness_probe):
            try:
                value = readiness_probe(tenant, request)
                if (
                    isinstance(value, Mapping)
                    and value.get("schema")
                    == "lightwork.privacy-rights-consumer-delivery-composition-status.v1"
                ):
                    composition = dict(value)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                pass

        return {
            "schema": "lightwork.privacy-rights-consumer-delivery-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            **RightsConsumerDeliveryStore.product_boundaries(),
            "raw_capability_returned_only_on_initial_mint": True,
            "capability_list_or_replay_endpoint_exposed": False,
            "public_consumer_endpoint_exposed": (
                composition.get("stock_vault_package_adapter_installed") is True
                and composition.get("public_subject_binding_resolver_installed") is True
            ),
            "tenant_or_principal_selector_accepted": False,
            "consumer_binding_selector_accepted": False,
            "live_customer_acceptance_verified": False,
            "status_request_opens_tenant_storage": False,
            "production_composition": composition,
        }

    @router.put(
        "/deliveries/{delivery_id}",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": MintDeliveryIn.model_json_schema()}},
            }
        },
    )
    async def mint_delivery(
        request: Request,
        response: Response,
        delivery_id: ObjectPath,
    ):
        require_global_permission(request, "admin")
        _private(response)
        body = await _body(request, MintDeliveryIn)
        assert isinstance(body, MintDeliveryIn)
        ops, tenant, store = authority(request)
        result = _expect(
            await call(
                ops,
                store.mint_delivery,
                tenant,
                body.case_id,
                body.package_id,
                delivery_id,
                reauthentication_receipt_sha256=body.reauthentication_receipt_sha256,
                ttl_seconds=body.ttl_seconds,
                retained_until=body.retained_until,
                max_attempts=body.max_attempts,
                min_attempt_interval_seconds=body.min_attempt_interval_seconds,
                idempotency_key=body.idempotency_key,
            ),
            ops.MintedRightsConsumerDelivery,
        )
        payload = _jsonable(result)
        if payload.get("capability_returned") is not True:
            payload["capability"] = None
        return payload

    @router.get("/deliveries/{delivery_id}")
    async def get_delivery(
        request: Request,
        response: Response,
        delivery_id: ObjectPath,
    ):
        require_permission(request, "view")
        _private(response)
        ops, tenant, store = authority(request)
        return _jsonable(
            _expect(
                await call(ops, store.get_delivery, tenant, delivery_id),
                ops.RightsConsumerDelivery,
            )
        )

    @router.post(
        "/deliveries/{delivery_id}/revoke",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": RevokeDeliveryIn.model_json_schema()}},
            }
        },
    )
    async def revoke_delivery(
        request: Request,
        response: Response,
        delivery_id: ObjectPath,
    ):
        require_global_permission(request, "admin")
        _private(response)
        body = await _body(request, RevokeDeliveryIn)
        assert isinstance(body, RevokeDeliveryIn)
        ops, tenant, store = authority(request)
        return _jsonable(
            _expect(
                await call(
                    ops,
                    store.revoke_delivery,
                    tenant,
                    delivery_id,
                    **body.model_dump(),
                ),
                ops.RightsConsumerDelivery,
            )
        )

    @router.put(
        "/deliveries/{delivery_id}/exports/{export_id}",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": ExportDeliveryIn.model_json_schema()}},
            }
        },
    )
    async def export_delivery(
        request: Request,
        response: Response,
        delivery_id: ObjectPath,
        export_id: ObjectPath,
    ):
        require_permission(request, "operate")
        _private(response)
        body = await _body(request, ExportDeliveryIn)
        assert isinstance(body, ExportDeliveryIn)
        ops, tenant, store = authority(request)
        return _jsonable(
            _expect(
                await call(
                    ops,
                    store.export_signed_metadata,
                    tenant,
                    delivery_id,
                    export_id,
                    **body.model_dump(),
                ),
                ops.SignedRightsConsumerDeliveryExport,
            )
        )

    @router.post("/deliveries/{delivery_id}/evidence-record")
    async def evidence_record(
        request: Request,
        response: Response,
        delivery_id: ObjectPath,
    ):
        """Signed metadata record for one link, signed with the deployment key
        (no bearer or object secret is ever included)."""

        require_permission(request, "operate")
        _private(response)
        body = await _body(request, EvidenceRecordIn)
        assert isinstance(body, EvidenceRecordIn)
        ops, tenant, store = authority(request)
        current = _expect(
            await call(ops, store.get_delivery, tenant, delivery_id),
            ops.RightsConsumerDelivery,
        )
        export_id = "evidence-" + hashlib.sha256(
            f"{delivery_id}:{body.idempotency_key}".encode()
        ).hexdigest()[:24]
        return _jsonable(
            _expect(
                await call(
                    ops,
                    store.export_signed_metadata,
                    tenant,
                    delivery_id,
                    export_id,
                    expected_delivery_revision=current.revision,
                    signing_key_ref=DEFAULT_EVIDENCE_SIGNING_KEY_REF,
                    retained_until=current.retained_until,
                    idempotency_key=body.idempotency_key,
                ),
                ops.SignedRightsConsumerDeliveryExport,
            )
        )

    @router.get("/exports/{export_id}")
    async def get_export(
        request: Request,
        response: Response,
        export_id: ObjectPath,
    ):
        require_global_permission(request, "audit")
        _private(response)
        ops, tenant, store = authority(request)
        return _jsonable(
            _expect(
                await call(ops, store.get_export, tenant, export_id),
                ops.SignedRightsConsumerDeliveryExport,
            )
        )

    @router.post(
        "/retention/purge",
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": PurgeDeliveryIn.model_json_schema()}},
            }
        },
    )
    async def purge_retention(
        request: Request,
        response: Response,
    ):
        require_global_permission(request, "admin")
        _private(response)
        body = await _body(request, PurgeDeliveryIn)
        assert isinstance(body, PurgeDeliveryIn)
        ops, tenant, store = authority(request)
        return _purge_result(await call(ops, store.purge_expired, tenant, **body.model_dump()))

    @router.get("/integrity")
    async def integrity(request: Request, response: Response):
        require_global_permission(request, "audit")
        _private(response)
        ops, tenant, store = authority(request)
        result = _jsonable(
            _expect(
                await call(ops, store.verify_integrity, tenant),
                ops.IntegrityVerification,
            )
        )
        result["valid"] = True
        return result

    return router


router = create_privacy_rights_consumer_delivery_router()

__all__ = [
    "DEFAULT_EVIDENCE_SIGNING_KEY_REF",
    "PrivacyRightsConsumerDeliveryDependencies",
    "create_privacy_rights_consumer_delivery_router",
    "privacy_rights_consumer_delivery_enabled_for_page",
    "router",
]
