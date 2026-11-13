"""Authenticated administration and public receipt-key metadata for native consent."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request, Response
from maverick.consent_native_sdk import (
    NativeConsentCapacityError,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentError,
    NativeConsentIntegrityError,
    NativeConsentValidationError,
)
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission
from .consent_native_composition import native_consent_principal_ref

router = APIRouter(prefix="/consent/native", tags=["native-consent-admin"])

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_PUBLIC_KEY_PATTERN = _DIGEST_PATTERN
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{1,87384}\Z")
_MAX_ATTESTATION_BYTES = 64 * 1_024
_PRIVATE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}

ApplicationRef = Annotated[
    str,
    Path(min_length=1, max_length=128, pattern=_REF_PATTERN),
]
DeviceRef = Annotated[
    str,
    Path(min_length=1, max_length=128, pattern=_REF_PATTERN),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NativeApplicationRegisterIn(_StrictModel):
    public_client_ref: str = Field(pattern=_REF_PATTERN)
    minimum_sdk_version: int = Field(ge=1, le=1_000_000)
    expected_revision: Literal[0]


class NativeReceiptKeyRotateIn(_StrictModel):
    expected_directory_revision: int = Field(ge=1, le=2**31 - 1)


class NativeDeviceRotateIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    public_key_hex: str = Field(pattern=_PUBLIC_KEY_PATTERN)
    attestation_nonce: str = Field(pattern=_REF_PATTERN)
    attestation_evidence_sha256: str = Field(pattern=_DIGEST_PATTERN)
    attestation_material_b64url: str = Field(
        min_length=1,
        max_length=87_384,
    )
    issued_at: float = Field(gt=0)
    expires_at: float = Field(gt=0)


class NativeDeviceRevokeIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    evidence_sha256: str = Field(pattern=_DIGEST_PATTERN)


def _private(response: Response) -> None:
    for name, value in _PRIVATE_HEADERS.items():
        response.headers[name] = value


def _tenant() -> str:
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "native_consent_tenant_required",
                "message": "select an active tenant before managing native consent",
            },
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    try:
        return native_consent_principal_ref(request, tenant_id)
    except NativeConsentError as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "native_consent_principal_required",
                "message": "authenticated principal authority is unavailable",
            },
        ) from exc


def _dependency(request: Request, name: str) -> Callable[..., Any]:
    selected = getattr(request.app.state, name, None)
    if not callable(selected):
        # Raised when called, inside the caller's error mapping, so a missing
        # composition is a 503 and not an unhandled error.
        def unavailable(*_args: Any, **_kwargs: Any) -> Any:
            raise NativeConsentIntegrityError("native consent composition is unavailable")

        return unavailable
    return selected


def _http_error(exc: NativeConsentError) -> HTTPException:
    if isinstance(exc, NativeConsentValidationError):
        status = 422
        code = "native_consent_invalid"
    elif isinstance(exc, NativeConsentConflict):
        status = 409
        code = "native_consent_conflict"
    elif isinstance(exc, NativeConsentDenied):
        status = 403
        code = "native_consent_denied"
    elif isinstance(exc, (NativeConsentCapacityError, NativeConsentIntegrityError)):
        status = 503
        code = "native_consent_unavailable"
    else:
        status = 503
        code = "native_consent_unavailable"
    return HTTPException(status_code=status, detail={"code": code, "message": str(exc)})


async def _call(function: Callable[..., Any], /, **kwargs: Any) -> Any:
    try:
        return await run_in_threadpool(function, **kwargs)
    except NativeConsentError as exc:
        raise _http_error(exc) from exc
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        error = NativeConsentIntegrityError("native consent operation is unavailable")
        raise _http_error(error) from exc


def _admin_authority(request: Request) -> tuple[str, str]:
    tenant = _tenant()
    return tenant, _principal(request, tenant)


def _decode_attestation(value: str) -> bytes:
    if _B64URL_RE.fullmatch(value) is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "native_consent_attestation_invalid",
                "message": "attestation material is invalid",
            },
        )
    try:
        material = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "native_consent_attestation_invalid",
                "message": "attestation material is invalid",
            },
        ) from exc
    if not 1 <= len(material) <= _MAX_ATTESTATION_BYTES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "native_consent_attestation_invalid",
                "message": "attestation material is invalid",
            },
        )
    return material


@router.get("/readiness")
async def readiness(request: Request, response: Response) -> dict[str, Any]:
    require_global_permission(request, "view")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_readiness"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
    )
    _private(response)
    if not isinstance(result, Mapping):
        raise _http_error(
            NativeConsentIntegrityError("native consent readiness is unavailable")
        )
    return dict(result)


@router.get("/applications")
async def list_applications(request: Request, response: Response) -> dict[str, Any]:
    """Registered applications for this workspace, for the page's record list."""

    require_global_permission(request, "audit")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_applications"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
    )
    _private(response)
    return dict(result)


@router.get("/applications/{application_ref}/devices")
async def list_devices(
    application_ref: ApplicationRef,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Enrolled devices of one application; no keys or install subjects."""

    require_global_permission(request, "audit")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_devices"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
        application_ref=application_ref,
    )
    _private(response)
    return dict(result)


@router.post("/applications", status_code=201)
async def register_application(
    body: NativeApplicationRegisterIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_register"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
        **body.model_dump(),
    )
    _private(response)
    return dict(result)


@router.post("/applications/{application_ref}/receipt-key/rotate")
async def rotate_receipt_key(
    application_ref: ApplicationRef,
    body: NativeReceiptKeyRotateIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_rotate_receipt_key"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
        application_ref=application_ref,
        expected_directory_revision=body.expected_directory_revision,
    )
    _private(response)
    return dict(result)


@router.post("/applications/{application_ref}/devices/{device_id}/rotate")
async def rotate_device(
    application_ref: ApplicationRef,
    device_id: DeviceRef,
    body: NativeDeviceRotateIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    tenant, principal = _admin_authority(request)
    payload = body.model_dump()
    material = _decode_attestation(payload.pop("attestation_material_b64url"))
    result = await _call(
        _dependency(request, "consent_native_admin_rotate_device"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
        application_ref=application_ref,
        device_id=device_id,
        attestation_material=material,
        **payload,
    )
    _private(response)
    return dict(result)


@router.post("/applications/{application_ref}/devices/{device_id}/revoke")
async def revoke_device(
    application_ref: ApplicationRef,
    device_id: DeviceRef,
    body: NativeDeviceRevokeIn,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_revoke_device"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
        application_ref=application_ref,
        device_id=device_id,
        **body.model_dump(),
    )
    _private(response)
    return dict(result)


@router.get("/integrity")
async def integrity(request: Request, response: Response) -> dict[str, Any]:
    require_global_permission(request, "audit")
    tenant, principal = _admin_authority(request)
    result = await _call(
        _dependency(request, "consent_native_admin_integrity"),
        request=request,
        tenant_id=tenant,
        principal_ref=principal,
    )
    _private(response)
    return dict(result)


def create_consent_native_public_metadata_router() -> APIRouter:
    """Expose only application-bound receipt verification keys."""

    public = APIRouter(
        prefix="/api/v1/public/consent/native",
        tags=["native-consent"],
    )

    @public.get("/receipt-keys")
    async def receipt_key_discovery(
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        """Describe the application-bound public-key discovery contract.

        The native-consent page links here before JavaScript has an
        application reference.  Keep the unparameterized GET useful without
        returning any tenant or key material; JavaScript replaces the link
        with the exact application URL after the operator supplies a reference.
        """

        if request.query_params:
            raise HTTPException(status_code=404, detail="not found")
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return {
            "schema": "lightwork.native-consent-receipt-key-discovery.v1",
            "method": "GET",
            "application_ref_required": True,
            "endpoint_template": (
                "/api/v1/public/consent/native/receipt-keys/{application_ref}"
            ),
        }

    @public.get("/receipt-keys/{application_ref}")
    async def receipt_keys(
        application_ref: Annotated[
            str,
            Path(min_length=1, max_length=128, pattern=_REF_PATTERN),
        ],
        request: Request,
        response: Response,
        cache_bust: Annotated[str | None, Query(include_in_schema=False)] = None,
    ) -> dict[str, Any]:
        # Query parameters cannot become key selectors.  ``cache_bust`` exists
        # only so FastAPI documents and rejects every supplied query uniformly.
        if cache_bust is not None or request.query_params:
            raise HTTPException(status_code=404, detail="not found")
        if (
            request.headers.get("authorization") is not None
            or request.headers.get("cookie") is not None
        ):
            raise HTTPException(status_code=401, detail="native consent authority unavailable")
        limiter = getattr(request.app.state, "consent_native_public_rate_limit", None)
        try:
            if not callable(limiter):
                raise NativeConsentIntegrityError("native consent rate limiter is unavailable")
            limiter(
                request.client.host if request.client is not None else "unknown",
                "receipt-keys",
            )
        except (NativeConsentDenied, NativeConsentCapacityError) as exc:
            raise HTTPException(
                status_code=429,
                detail="native consent rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        except NativeConsentError as exc:
            raise HTTPException(
                status_code=503,
                detail="native consent keys unavailable",
            ) from exc
        try:
            result = await run_in_threadpool(
                _dependency(request, "consent_native_public_receipt_keys"),
                application_ref,
            )
        except NativeConsentDenied as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except NativeConsentConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="native consent authority changed",
            ) from exc
        except NativeConsentError as exc:
            raise HTTPException(
                status_code=503,
                detail="native consent keys unavailable",
            ) from exc
        if not isinstance(result, Mapping):
            raise HTTPException(status_code=503, detail="native consent keys unavailable")
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return dict(result)

    return public


__all__ = [
    "NativeApplicationRegisterIn",
    "NativeDeviceRevokeIn",
    "NativeDeviceRotateIn",
    "NativeReceiptKeyRotateIn",
    "create_consent_native_public_metadata_router",
    "router",
]
